"""Shared fixtures for agent and tools tests."""

import sys
import os
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

# Add src/ to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent import Config


@pytest.fixture
def mock_config():
    """Returns a Config with test values (no real API keys)."""
    return Config(
        es_host="https://localhost:9200",
        es_user="elastic",
        es_password="test-password",
        es_index="test-security-logs",
        verify_certs=False,
        anthropic_api_key="sk-ant-test-key",
        abuseipdb_api_key="test-abuseipdb-key",
        github_token="ghp_test-token",
        model="claude-sonnet-4-5-20250929",
        max_iterations=5,
        github_repo="testowner/testrepo",
    )


@pytest.fixture
def mock_es_client():
    """Returns a MagicMock Elasticsearch client with pre-configured responses."""
    es = MagicMock()

    # Default search response (empty)
    es.search.return_value = {
        "hits": {
            "total": {"value": 0},
            "hits": [],
        },
        "aggregations": {
            "by_ip": {"buckets": []},
        },
    }

    # Default mget response
    es.mget.return_value = {"docs": []}

    # Default info response
    es.info.return_value = {"version": {"number": "8.12.0"}}

    return es


@pytest.fixture
def sample_events():
    """Returns a list of realistic security event dicts (brute force pattern)."""
    base_event = {
        "event_type": "authentication",
        "source_geo": {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
        "destination_host": "app-server-01",
        "auth_method": "ssh",
    }

    events = []
    # 10 failures from one IP against admin
    for i in range(10):
        events.append(
            {
                **base_event,
                "timestamp": f"2025-01-15T10:{i:02d}:00.000000Z",
                "outcome": "failure",
                "source_ip": "185.220.101.42",
                "username": "admin",
                "failure_reason": "invalid_password",
                "attack_pattern": "brute_force",
            }
        )
    # 3 normal successes from a legitimate IP
    for i in range(3):
        events.append(
            {
                **base_event,
                "timestamp": f"2025-01-15T10:{10 + i:02d}:00.000000Z",
                "outcome": "success",
                "source_ip": "203.0.113.50",
                "username": "jsmith",
                "failure_reason": None,
                "session_id": f"abc{i}",
                "attack_pattern": None,
            }
        )
    return events


@pytest.fixture
def sample_search_response(sample_events):
    """Returns a mock ES search response containing sample_events."""
    return {
        "hits": {
            "total": {"value": len(sample_events)},
            "hits": [
                {"_id": f"doc_{i}", "_source": event}
                for i, event in enumerate(sample_events)
            ],
        },
    }


@pytest.fixture
def sample_aggregation_response():
    """Returns a mock ES aggregation response with 2 suspicious IPs."""
    return {
        "hits": {"total": {"value": 60}, "hits": []},
        "aggregations": {
            "by_ip": {
                "buckets": [
                    {
                        "key": "185.220.101.42",
                        "doc_count": 50,
                        "earliest": {"value_as_string": "2025-01-15T10:00:00.000Z"},
                        "latest": {"value_as_string": "2025-01-15T10:05:00.000Z"},
                    },
                    {
                        "key": "45.155.205.117",
                        "doc_count": 25,
                        "earliest": {"value_as_string": "2025-01-15T10:01:00.000Z"},
                        "latest": {"value_as_string": "2025-01-15T10:04:00.000Z"},
                    },
                ],
            },
        },
    }
