"""
Integration tests for ES tools — requires a running Elasticsearch cluster.
Run: pytest tests/test_integration.py -v
Skip: pytest tests/ -v --ignore=tests/test_integration.py

Requires ES_HOST and ES_PASSWORD environment variables (or .env file).
"""

import json
import os
import sys
import uuid
import warnings
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from agent import Config
from tools import _search_security_logs, _aggregate_failed_logins, _get_event_details
from data_generator import create_index_mapping, format_timestamp_es

warnings.filterwarnings("ignore")
load_dotenv()

pytestmark = pytest.mark.integration


# =============================================================================
# Fixtures
# =============================================================================

def _es_available():
    """Check if ES is reachable."""
    host = os.getenv("ES_HOST", "https://localhost:9200")
    password = os.getenv("ES_PASSWORD", "")
    if not password:
        return False
    try:
        es = Elasticsearch(host, basic_auth=("elastic", password), verify_certs=False)
        es.info()
        return True
    except Exception:
        return False


skip_no_es = pytest.mark.skipif(
    not _es_available(),
    reason="Elasticsearch not available (set ES_HOST and ES_PASSWORD)",
)


@pytest.fixture(scope="session")
def es_test_env():
    """
    Session-scoped fixture: creates a temporary test index, seeds it with
    known attack data, and tears it down after all tests.
    """
    host = os.getenv("ES_HOST", "https://localhost:9200")
    password = os.getenv("ES_PASSWORD", "")
    index_name = f"test-security-logs-{uuid.uuid4().hex[:8]}"

    es = Elasticsearch(host, basic_auth=("elastic", password), verify_certs=False)
    es.indices.create(index=index_name, body=create_index_mapping())

    config = Config(
        es_host=host,
        es_user="elastic",
        es_password=password,
        es_index=index_name,
        verify_certs=False,
    )

    now = datetime.now(timezone.utc)

    # Seed data: brute force attack from 185.220.101.42 against admin (50 failures)
    brute_force_events = []
    for i in range(50):
        ts = now - timedelta(minutes=10) + timedelta(seconds=i * 5)
        brute_force_events.append({
            "timestamp": format_timestamp_es(ts),
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "185.220.101.42",
            "source_geo": {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
            "destination_host": "app-server-01",
            "username": "admin",
            "auth_method": "ssh",
            "failure_reason": "invalid_password",
            "attack_pattern": "brute_force",
        })

    # Seed data: normal traffic (20 successes from legitimate IPs)
    normal_events = []
    for i in range(20):
        ts = now - timedelta(minutes=15) + timedelta(seconds=i * 30)
        normal_events.append({
            "timestamp": format_timestamp_es(ts),
            "event_type": "authentication",
            "outcome": "success",
            "source_ip": "203.0.113.50",
            "source_geo": {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
            "destination_host": "web-frontend-01",
            "username": "jsmith",
            "auth_method": "web_login",
            "session_id": f"session_{i}",
        })

    # Seed data: old event (2 hours ago — should be excluded by time window)
    old_event = {
        "timestamp": format_timestamp_es(now - timedelta(hours=2)),
        "event_type": "authentication",
        "outcome": "failure",
        "source_ip": "45.155.205.117",
        "source_geo": {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
        "destination_host": "db-primary",
        "username": "root",
        "auth_method": "ssh",
        "failure_reason": "invalid_password",
        "attack_pattern": "brute_force",
    }

    # Bulk index
    all_events = brute_force_events + normal_events + [old_event]
    actions = [{"_index": index_name, "_source": event} for event in all_events]
    from elasticsearch.helpers import bulk
    bulk(es, actions)

    # Refresh to make searchable immediately
    es.indices.refresh(index=index_name)

    # Yield test context
    yield {
        "es": es,
        "config": config,
        "index": index_name,
        "brute_force_ip": "185.220.101.42",
        "brute_force_count": 50,
        "normal_ip": "203.0.113.50",
        "old_event_ip": "45.155.205.117",
    }

    # Teardown
    es.indices.delete(index=index_name, ignore=[404])


# =============================================================================
# search_security_logs integration tests
# =============================================================================

@skip_no_es
class TestSearchIntegration:
    def test_search_finds_failures(self, es_test_env):
        """Search for failures — should find the brute force events."""
        result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"outcome": "failure", "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        assert parsed["total"] >= es_test_env["brute_force_count"]

    def test_search_filters_by_ip(self, es_test_env):
        """Search by source_ip — should return only matching events."""
        result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"source_ip": es_test_env["brute_force_ip"], "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        for event in parsed["events"]:
            assert event["source_ip"] == es_test_env["brute_force_ip"]

    def test_search_filters_by_username(self, es_test_env):
        """Search by username — should return only matching events."""
        result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"username": "admin", "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        for event in parsed["events"]:
            assert event["username"] == "admin"

    def test_search_time_window_excludes_old(self, es_test_env):
        """Old event (2 hours ago) should not appear in a 30-minute window."""
        result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"source_ip": es_test_env["old_event_ip"], "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        assert parsed["total"] == 0

    def test_search_max_results(self, es_test_env):
        """max_results=5 should return exactly 5 even though more exist."""
        result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"max_results": 5, "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        assert len(parsed["events"]) == 5


# =============================================================================
# aggregate_failed_logins integration tests
# =============================================================================

@skip_no_es
class TestAggregateIntegration:
    def test_aggregate_detects_brute_force_ip(self, es_test_env):
        """Aggregate with threshold=10 — brute force IP should appear."""
        result = _aggregate_failed_logins(
            es_test_env["es"], es_test_env["config"],
            {"threshold": 10, "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        ips = [entry["ip"] for entry in parsed["suspicious_ips"]]
        assert es_test_env["brute_force_ip"] in ips

        # Check count is approximately right
        bf_entry = next(e for e in parsed["suspicious_ips"] if e["ip"] == es_test_env["brute_force_ip"])
        assert bf_entry["count"] == es_test_env["brute_force_count"]

    def test_aggregate_threshold_filters(self, es_test_env):
        """Aggregate with threshold=100 — brute force IP (~50) should be excluded."""
        result = _aggregate_failed_logins(
            es_test_env["es"], es_test_env["config"],
            {"threshold": 100, "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        ips = [entry["ip"] for entry in parsed["suspicious_ips"]]
        assert es_test_env["brute_force_ip"] not in ips

    def test_aggregate_returns_timestamps(self, es_test_env):
        """Each bucket should include earliest and latest timestamps."""
        result = _aggregate_failed_logins(
            es_test_env["es"], es_test_env["config"],
            {"threshold": 10, "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        for entry in parsed["suspicious_ips"]:
            assert "earliest" in entry
            assert "latest" in entry
            assert entry["earliest"] is not None


# =============================================================================
# get_event_details integration tests
# =============================================================================

@skip_no_es
class TestGetEventDetailsIntegration:
    def test_get_by_ids_returns_documents(self, es_test_env):
        """Index a known event, retrieve by ID, verify fields match."""
        # First search to get a real document ID
        search_result = _search_security_logs(
            es_test_env["es"], es_test_env["config"],
            {"source_ip": es_test_env["brute_force_ip"], "max_results": 1, "time_window_minutes": 30},
        )
        doc_id = json.loads(search_result)["events"][0]["_id"]

        # Now retrieve by ID
        result = _get_event_details(
            es_test_env["es"], es_test_env["config"],
            {"event_ids": [doc_id]},
        )
        parsed = json.loads(result)
        assert parsed["total"] == 1
        assert parsed["events"][0]["source_ip"] == es_test_env["brute_force_ip"]

    def test_get_by_ip_returns_events(self, es_test_env):
        """Retrieve events by source_ip — should match seeded data."""
        result = _get_event_details(
            es_test_env["es"], es_test_env["config"],
            {"source_ip": es_test_env["brute_force_ip"], "time_window_minutes": 30},
        )
        parsed = json.loads(result)
        assert parsed["total"] >= es_test_env["brute_force_count"]
        for event in parsed["events"]:
            assert event["source_ip"] == es_test_env["brute_force_ip"]
