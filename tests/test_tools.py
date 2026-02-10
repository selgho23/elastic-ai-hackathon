"""Unit tests for tools.py — all external dependencies are mocked."""

import json
from unittest.mock import patch, MagicMock

import pytest

from tools import (
    TOOL_SCHEMAS,
    execute_tool,
    _search_security_logs,
    _aggregate_failed_logins,
    _get_event_details,
    _check_ip_reputation,
    _create_incident_report,
)


# =============================================================================
# search_security_logs tests
# =============================================================================

class TestSearchSecurityLogs:
    def test_search_builds_correct_query(self, mock_es_client, mock_config, sample_search_response):
        """Verify the ES bool query includes the right must clauses when all filters provided."""
        mock_es_client.search.return_value = sample_search_response

        _search_security_logs(mock_es_client, mock_config, {
            "source_ip": "185.220.101.42",
            "outcome": "failure",
            "username": "admin",
        })

        call_kwargs = mock_es_client.search.call_args
        body = call_kwargs.kwargs.get("body") or call_kwargs[1].get("body")
        must = body["query"]["bool"]["must"]

        # Should have 4 clauses: range + outcome + source_ip + username
        assert len(must) == 4
        terms = {
            field: value
            for clause in must if "term" in clause
            for field, value in clause["term"].items()
        }
        assert terms["outcome"] == "failure"
        assert terms["source_ip"] == "185.220.101.42"
        assert terms["username"] == "admin"

    def test_search_time_window(self, mock_es_client, mock_config, sample_search_response):
        """Verify the range filter uses the correct time window."""
        mock_es_client.search.return_value = sample_search_response

        _search_security_logs(mock_es_client, mock_config, {"time_window_minutes": 60})

        body = mock_es_client.search.call_args.kwargs.get("body") or mock_es_client.search.call_args[1]["body"]
        range_clause = body["query"]["bool"]["must"][0]
        assert range_clause["range"]["timestamp"]["gte"] == "now-60m"

    def test_search_respects_max_results(self, mock_es_client, mock_config, sample_search_response):
        """Verify size parameter is passed to ES."""
        mock_es_client.search.return_value = sample_search_response

        _search_security_logs(mock_es_client, mock_config, {"max_results": 10})

        body = mock_es_client.search.call_args.kwargs.get("body") or mock_es_client.search.call_args[1]["body"]
        assert body["size"] == 10

    def test_search_no_filters(self, mock_es_client, mock_config, sample_search_response):
        """Verify omitting all optional filters produces a valid query (just time range)."""
        mock_es_client.search.return_value = sample_search_response

        _search_security_logs(mock_es_client, mock_config, {})

        body = mock_es_client.search.call_args.kwargs.get("body") or mock_es_client.search.call_args[1]["body"]
        must = body["query"]["bool"]["must"]
        assert len(must) == 1  # Only the range clause
        assert "range" in must[0]

    def test_search_returns_json(self, mock_es_client, mock_config, sample_search_response):
        """Verify return value is valid JSON with expected structure."""
        mock_es_client.search.return_value = sample_search_response

        result = _search_security_logs(mock_es_client, mock_config, {})
        parsed = json.loads(result)

        assert "total" in parsed
        assert "events" in parsed
        assert parsed["total"] == len(sample_search_response["hits"]["hits"])


# =============================================================================
# aggregate_failed_logins tests
# =============================================================================

class TestAggregateFailedLogins:
    def test_aggregate_builds_terms_agg(self, mock_es_client, mock_config, sample_aggregation_response):
        """Verify terms aggregation on source_ip with min_doc_count."""
        mock_es_client.search.return_value = sample_aggregation_response

        _aggregate_failed_logins(mock_es_client, mock_config, {"threshold": 10})

        body = mock_es_client.search.call_args.kwargs.get("body") or mock_es_client.search.call_args[1]["body"]
        agg = body["aggs"]["by_ip"]["terms"]
        assert agg["field"] == "source_ip"
        assert agg["min_doc_count"] == 10

    def test_aggregate_filters_by_failure(self, mock_es_client, mock_config, sample_aggregation_response):
        """Verify the query filters on outcome: failure."""
        mock_es_client.search.return_value = sample_aggregation_response

        _aggregate_failed_logins(mock_es_client, mock_config, {})

        body = mock_es_client.search.call_args.kwargs.get("body") or mock_es_client.search.call_args[1]["body"]
        must = body["query"]["bool"]["must"]
        term_clauses = [c for c in must if "term" in c]
        assert any(c["term"]["outcome"] == "failure" for c in term_clauses)

    def test_aggregate_returns_ip_list(self, mock_es_client, mock_config, sample_aggregation_response):
        """Verify return value is a JSON list of {ip, count, earliest, latest}."""
        mock_es_client.search.return_value = sample_aggregation_response

        result = _aggregate_failed_logins(mock_es_client, mock_config, {})
        parsed = json.loads(result)

        assert parsed["total_suspicious"] == 2
        ip_entry = parsed["suspicious_ips"][0]
        assert "ip" in ip_entry
        assert "count" in ip_entry
        assert "earliest" in ip_entry
        assert "latest" in ip_entry

    def test_aggregate_empty_result(self, mock_es_client, mock_config):
        """Verify graceful handling when no IPs exceed threshold."""
        mock_es_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"by_ip": {"buckets": []}},
        }

        result = _aggregate_failed_logins(mock_es_client, mock_config, {"threshold": 100})
        parsed = json.loads(result)

        assert parsed["suspicious_ips"] == []
        assert parsed["total_suspicious"] == 0


# =============================================================================
# get_event_details tests
# =============================================================================

class TestGetEventDetails:
    def test_get_by_event_ids(self, mock_es_client, mock_config):
        """Verify mget is called with provided IDs."""
        mock_es_client.mget.return_value = {
            "docs": [
                {"_id": "doc_1", "found": True, "_source": {"username": "admin"}},
            ],
        }

        result = _get_event_details(mock_es_client, mock_config, {"event_ids": ["doc_1"]})
        parsed = json.loads(result)

        mock_es_client.mget.assert_called_once_with(index="test-security-logs", ids=["doc_1"])
        assert parsed["total"] == 1
        assert parsed["events"][0]["_id"] == "doc_1"

    def test_get_by_source_ip(self, mock_es_client, mock_config, sample_search_response):
        """Verify fallback to bool query when source_ip provided instead of IDs."""
        mock_es_client.search.return_value = sample_search_response

        result = _get_event_details(mock_es_client, mock_config, {"source_ip": "185.220.101.42"})
        parsed = json.loads(result)

        mock_es_client.search.assert_called_once()
        assert parsed["total"] > 0

    def test_get_returns_full_documents(self, mock_es_client, mock_config):
        """Verify all event fields are present in returned JSON."""
        mock_es_client.mget.return_value = {
            "docs": [
                {
                    "_id": "doc_1",
                    "found": True,
                    "_source": {
                        "timestamp": "2025-01-15T10:00:00.000000Z",
                        "event_type": "authentication",
                        "outcome": "failure",
                        "source_ip": "185.220.101.42",
                        "username": "admin",
                    },
                },
            ],
        }

        result = _get_event_details(mock_es_client, mock_config, {"event_ids": ["doc_1"]})
        parsed = json.loads(result)
        event = parsed["events"][0]

        assert event["timestamp"] == "2025-01-15T10:00:00.000000Z"
        assert event["source_ip"] == "185.220.101.42"
        assert event["username"] == "admin"


# =============================================================================
# check_ip_reputation tests
# =============================================================================

class TestCheckIpReputation:
    @patch("tools.requests.get")
    def test_reputation_success(self, mock_get, mock_config):
        """Mock a 200 response from AbuseIPDB."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "ipAddress": "185.220.101.42",
                    "abuseConfidenceScore": 95,
                    "countryCode": "DE",
                    "isp": "Hetzner",
                    "totalReports": 142,
                    "lastReportedAt": "2025-01-15T10:00:00+00:00",
                    "isWhitelisted": False,
                },
            },
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = _check_ip_reputation(mock_config, {"ip_address": "185.220.101.42"})
        parsed = json.loads(result)

        assert parsed["abuse_confidence_score"] == 95
        assert parsed["total_reports"] == 142
        assert parsed["country_code"] == "DE"

    @patch("tools.requests.get")
    def test_reputation_rate_limit(self, mock_get, mock_config):
        """Mock a 429 response — should return structured error."""
        mock_get.return_value = MagicMock(status_code=429)

        result = _check_ip_reputation(mock_config, {"ip_address": "1.2.3.4"})
        parsed = json.loads(result)

        assert "error" in parsed
        assert "rate limit" in parsed["error"].lower()

    @patch("tools.requests.get")
    def test_reputation_network_error(self, mock_get, mock_config):
        """Mock a ConnectionError — should return structured error."""
        import requests as req
        mock_get.side_effect = req.ConnectionError("Connection refused")

        result = _check_ip_reputation(mock_config, {"ip_address": "1.2.3.4"})
        parsed = json.loads(result)

        assert "error" in parsed


# =============================================================================
# create_incident_report tests
# =============================================================================

class TestCreateIncidentReport:
    REPORT_INPUT = {
        "title": "Brute Force Attack Detected",
        "summary": "IP 185.220.101.42 attempted 50 failed logins against admin.",
        "affected_ips": ["185.220.101.42"],
        "attack_type": "brute_force",
        "severity": "high",
        "recommendations": ["Block IP at firewall", "Reset admin password"],
    }

    @patch("tools.requests.post")
    def test_report_creates_issue(self, mock_post, mock_config):
        """Mock a 201 response from GitHub."""
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {
                "number": 42,
                "html_url": "https://github.com/testowner/testrepo/issues/42",
                "created_at": "2025-01-15T10:30:00Z",
                "state": "open",
            },
        )
        mock_post.return_value.raise_for_status = MagicMock()

        result = _create_incident_report(mock_config, self.REPORT_INPUT)
        parsed = json.loads(result)

        assert parsed["issue_number"] == 42
        assert "testowner/testrepo" in parsed["issue_url"]

        # Verify the POST was made with correct URL and auth
        call_kwargs = mock_post.call_args
        assert "testowner/testrepo" in call_kwargs.args[0]
        assert "Bearer" in call_kwargs.kwargs["headers"]["Authorization"]

    @patch("tools.requests.post")
    def test_report_labels(self, mock_post, mock_config):
        """Verify the issue is created with correct labels."""
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"number": 1, "html_url": "https://example.com", "created_at": "2025-01-15", "state": "open"},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        _create_incident_report(mock_config, self.REPORT_INPUT)

        call_kwargs = mock_post.call_args
        labels = call_kwargs.kwargs["json"]["labels"]
        assert "security-incident" in labels
        assert "high" in labels

    @patch("tools.requests.post")
    def test_report_api_error(self, mock_post, mock_config):
        """Mock a 403 response — should return structured error."""
        mock_post.return_value = MagicMock(status_code=403, text="Forbidden")

        result = _create_incident_report(mock_config, self.REPORT_INPUT)
        parsed = json.loads(result)

        assert "error" in parsed


# =============================================================================
# execute_tool dispatcher tests
# =============================================================================

class TestExecuteTool:
    def test_dispatch_known_tools(self, mock_es_client, mock_config, sample_search_response):
        """Verify dispatching to each known tool name works."""
        mock_es_client.search.return_value = sample_search_response
        mock_es_client.mget.return_value = {"docs": []}

        for name in ["search_security_logs", "aggregate_failed_logins", "get_event_details"]:
            result = execute_tool(name, {}, mock_es_client, mock_config)
            parsed = json.loads(result)
            assert "error" not in parsed or "required" in parsed.get("error", "")

    def test_dispatch_unknown_tool(self, mock_es_client, mock_config):
        """Verify an unknown tool name returns a JSON error."""
        result = execute_tool("nonexistent_tool", {}, mock_es_client, mock_config)
        parsed = json.loads(result)

        assert "error" in parsed
        assert "Unknown tool" in parsed["error"]
