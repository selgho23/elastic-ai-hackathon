#!/usr/bin/env python3
"""
Tool schemas and implementations for the Incident Response Agent.
Each tool has a JSON schema (for Anthropic tool_use API) and an implementation
function that returns a JSON string.
"""

import json
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

# =============================================================================
# Tool Schemas (for Anthropic API tools parameter)
# =============================================================================

TOOL_SCHEMAS = [
    {
        "name": "search_security_logs",
        "description": (
            "Search Elasticsearch security logs with optional filters. "
            "Use this to investigate specific IPs, users, or event patterns "
            "after detection. Returns matching log events sorted by timestamp."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "time_window_minutes": {
                    "type": "integer",
                    "description": "How far back to search (in minutes from now). Default 30.",
                    "default": 30,
                },
                "outcome": {
                    "type": "string",
                    "enum": ["success", "failure"],
                    "description": "Filter by authentication outcome.",
                },
                "source_ip": {
                    "type": "string",
                    "description": "Filter by source IP address.",
                },
                "username": {
                    "type": "string",
                    "description": "Filter by username.",
                },
                "event_type": {
                    "type": "string",
                    "description": "Filter by event type (e.g. 'authentication').",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of events to return. Default 200.",
                    "default": 200,
                },
            },
            "required": [],
        },
    },
    {
        "name": "aggregate_failed_logins",
        "description": (
            "Find source IPs with failed login counts exceeding a threshold. "
            "Uses Elasticsearch aggregations to process all events server-side. "
            "Start with this tool to detect suspicious activity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "time_window_minutes": {
                    "type": "integer",
                    "description": "How far back to search (in minutes from now). Default 30.",
                    "default": 30,
                },
                "threshold": {
                    "type": "integer",
                    "description": "Minimum number of failed logins to flag an IP. Default 5.",
                    "default": 5,
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_event_details",
        "description": (
            "Retrieve full details of specific security events by their IDs, "
            "or by source IP within a time window."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of Elasticsearch document IDs to retrieve.",
                },
                "source_ip": {
                    "type": "string",
                    "description": "Source IP to query events for (used if event_ids not provided).",
                },
                "time_window_minutes": {
                    "type": "integer",
                    "description": "Time window for source_ip query (minutes). Default 30.",
                    "default": 30,
                },
            },
            "required": [],
        },
    },
    {
        "name": "check_ip_reputation",
        "description": (
            "Query AbuseIPDB for threat intelligence on an IP address. "
            "Returns abuse confidence score, country, ISP, and report count."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to check.",
                },
                "max_age_days": {
                    "type": "integer",
                    "description": "How many days back to include reports (1-365). Default 90.",
                    "default": 90,
                },
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "create_incident_report",
        "description": (
            "Create a GitHub issue with a formatted incident report. "
            "Use this after confirming a threat to document findings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Issue title summarizing the incident.",
                },
                "summary": {
                    "type": "string",
                    "description": "Detailed narrative summary of the incident.",
                },
                "affected_ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of source IPs involved in the incident.",
                },
                "attack_type": {
                    "type": "string",
                    "description": "Classification: brute_force, credential_stuffing, password_spraying, lateral_movement, or impossible_travel.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Incident severity level.",
                },
                "recommendations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of recommended remediation actions.",
                },
            },
            "required": ["title", "summary", "affected_ips", "attack_type", "severity", "recommendations"],
        },
    },
]


# =============================================================================
# Tool Implementations
# =============================================================================

def _search_security_logs(es_client, config, tool_input: dict) -> str:
    time_window = tool_input.get("time_window_minutes", 30)
    max_results = tool_input.get("max_results", 200)

    must_clauses = [
        {"range": {"timestamp": {"gte": f"now-{time_window}m", "lte": "now"}}},
    ]

    if "outcome" in tool_input:
        must_clauses.append({"term": {"outcome": tool_input["outcome"]}})
    if "source_ip" in tool_input:
        must_clauses.append({"term": {"source_ip": tool_input["source_ip"]}})
    if "username" in tool_input:
        must_clauses.append({"term": {"username": tool_input["username"]}})
    if "event_type" in tool_input:
        must_clauses.append({"term": {"event_type": tool_input["event_type"]}})

    query = {
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": max_results,
    }

    result = es_client.search(index=config.es_index, body=query)
    hits = [
        {"_id": hit["_id"], **hit["_source"]}
        for hit in result["hits"]["hits"]
    ]
    return json.dumps({"total": result["hits"]["total"]["value"], "events": hits})


def _aggregate_failed_logins(es_client, config, tool_input: dict) -> str:
    time_window = tool_input.get("time_window_minutes", 30)
    threshold = tool_input.get("threshold", 5)

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": f"now-{time_window}m", "lte": "now"}}},
                    {"term": {"outcome": "failure"}},
                ],
            },
        },
        "size": 0,
        "aggs": {
            "by_ip": {
                "terms": {
                    "field": "source_ip",
                    "min_doc_count": threshold,
                    "size": 100,
                },
                "aggs": {
                    "earliest": {"min": {"field": "timestamp"}},
                    "latest": {"max": {"field": "timestamp"}},
                },
            },
        },
    }

    result = es_client.search(index=config.es_index, body=query)
    buckets = result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    ips = [
        {
            "ip": bucket["key"],
            "count": bucket["doc_count"],
            "earliest": bucket["earliest"]["value_as_string"],
            "latest": bucket["latest"]["value_as_string"],
        }
        for bucket in buckets
    ]
    return json.dumps({"suspicious_ips": ips, "total_suspicious": len(ips)})


def _get_event_details(es_client, config, tool_input: dict) -> str:
    event_ids = tool_input.get("event_ids")

    if event_ids:
        result = es_client.mget(index=config.es_index, ids=event_ids)
        docs = [
            {"_id": doc["_id"], **doc["_source"]}
            for doc in result["docs"]
            if doc.get("found")
        ]
        return json.dumps({"events": docs, "total": len(docs)})

    # Fallback: query by source_ip
    source_ip = tool_input.get("source_ip")
    if not source_ip:
        return json.dumps({"error": "Either event_ids or source_ip is required."})

    time_window = tool_input.get("time_window_minutes", 30)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": f"now-{time_window}m", "lte": "now"}}},
                    {"term": {"source_ip": source_ip}},
                ],
            },
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 200,
    }
    result = es_client.search(index=config.es_index, body=query)
    hits = [
        {"_id": hit["_id"], **hit["_source"]}
        for hit in result["hits"]["hits"]
    ]
    return json.dumps({"events": hits, "total": len(hits)})


def _check_ip_reputation(config, tool_input: dict) -> str:
    ip_address = tool_input["ip_address"]
    max_age_days = tool_input.get("max_age_days", 90)

    if not config.abuseipdb_api_key:
        return json.dumps({"error": "ABUSEIPDB_API_KEY not configured."})

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": ""},
            headers={"Key": config.abuseipdb_api_key, "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 429:
            return json.dumps({"error": "AbuseIPDB rate limit exceeded. Try again later."})
        resp.raise_for_status()
        data = resp.json()["data"]
        return json.dumps({
            "ip": data["ipAddress"],
            "abuse_confidence_score": data["abuseConfidenceScore"],
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted", False),
        })
    except requests.ConnectionError:
        return json.dumps({"error": f"Failed to connect to AbuseIPDB for IP {ip_address}."})
    except requests.RequestException as e:
        return json.dumps({"error": f"AbuseIPDB request failed: {str(e)}"})


def _create_incident_report(config, tool_input: dict) -> str:
    if not config.github_token:
        return json.dumps({"error": "GITHUB_TOKEN not configured."})
    if not config.github_repo:
        return json.dumps({"error": "GITHUB_REPO not configured."})

    title = tool_input["title"]
    summary = tool_input["summary"]
    affected_ips = tool_input["affected_ips"]
    attack_type = tool_input["attack_type"]
    severity = tool_input["severity"]
    recommendations = tool_input["recommendations"]

    # Format markdown body
    ip_rows = "\n".join(f"| {ip} |" for ip in affected_ips)
    rec_items = "\n".join(f"- {r}" for r in recommendations)

    body = f"""## Summary

{summary}

## Attack Classification

- **Type**: {attack_type}
- **Severity**: {severity.upper()}
- **Detected at**: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

## Affected IPs

| Source IP |
|-----------|
{ip_rows}

## Recommendations

{rec_items}
"""

    try:
        resp = requests.post(
            f"https://api.github.com/repos/{config.github_repo}/issues",
            json={
                "title": title,
                "body": body,
                "labels": ["security-incident", severity],
            },
            headers={
                "Authorization": f"Bearer {config.github_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        if resp.status_code == 403:
            return json.dumps({"error": f"GitHub API forbidden: {resp.text}"})
        resp.raise_for_status()
        result = resp.json()
        return json.dumps({
            "issue_number": result["number"],
            "issue_url": result["html_url"],
            "created_at": result["created_at"],
            "state": result["state"],
        })
    except requests.RequestException as e:
        return json.dumps({"error": f"GitHub API request failed: {str(e)}"})


# =============================================================================
# Tool Dispatcher
# =============================================================================

def execute_tool(name: str, tool_input: dict, es_client, config) -> str:
    """Dispatch a tool call by name. Returns a JSON string."""
    try:
        if name == "search_security_logs":
            return _search_security_logs(es_client, config, tool_input)
        elif name == "aggregate_failed_logins":
            return _aggregate_failed_logins(es_client, config, tool_input)
        elif name == "get_event_details":
            return _get_event_details(es_client, config, tool_input)
        elif name == "check_ip_reputation":
            return _check_ip_reputation(config, tool_input)
        elif name == "create_incident_report":
            return _create_incident_report(config, tool_input)
        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        logger.exception(f"Tool {name} failed")
        return json.dumps({"error": f"Tool {name} failed: {str(e)}"})
