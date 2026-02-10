# Incident Response Agent — Implementation Plan

## Context

Build an AI agent (`src/agent.py`) that detects security incidents from Elasticsearch data, enriches findings with threat intelligence (AbuseIPDB), and creates GitHub issues. The agent uses Claude's `tool_use` API with a manual agentic loop for full control and transparency.

## File Structure

```
src/
  agent.py          → Main entry point: config, CLI, agentic loop, system prompt
  tools.py          → Tool JSON schemas + implementation functions
  requirements.txt  → Updated with new dependencies
tests/
  conftest.py            → Shared fixtures (mock ES client, mock config, sample events)
  test_tools.py          → Unit tests for all 5 tools (mocked, no external deps)
  test_agent.py          → Unit tests for agentic loop, config, CLI parsing
  test_integration.py    → Integration tests for ES tools (requires running ES cluster)
.env               → API keys (ANTHROPIC_API_KEY, ABUSEIPDB_API_KEY, GITHUB_TOKEN)
```

Two source files keeps it lightweight (hackathon-appropriate) while separating orchestration from tool logic.

---

## Step 1: Update `src/requirements.txt`

Add dependencies:

```
elasticsearch>=8.0.0
anthropic>=0.45.0
requests>=2.31.0
python-dotenv>=1.0.0
pytest>=8.0.0
pytest-mock>=3.12.0
```

---

## Step 2: Create `src/tools.py` — Tool Schemas and Implementations

Define 5 tools, each as a pair: a JSON schema dict (for the Anthropic API) and an implementation function that returns a JSON string.

### Tool 1: `search_security_logs`
- **Purpose**: Query ES for security events matching filters
- **Inputs**: `time_window_minutes` (int, default 30), `outcome` (optional: "success"/"failure"), `source_ip` (optional), `username` (optional), `event_type` (optional), `max_results` (int, default 200)
- **Implementation**: Build an ES bool query with optional `must` clauses from the inputs. Use `range` filter on `timestamp` for the time window. Sort by timestamp desc. Return matching hits as JSON.
- **Note**: This tool is for targeted investigation *after* `aggregate_failed_logins` identifies suspicious IPs. The 200-event default covers a full brute force sequence (~50 events) with room to spare. The `aggregate_failed_logins` tool handles detection via server-side ES aggregations with no result cap.
- **ES pattern**: Reuse the `Elasticsearch(host, basic_auth=(...), verify_certs=...)` pattern from `data_generator.py`

### Tool 2: `aggregate_failed_logins`
- **Purpose**: Find source IPs with failed logins exceeding a threshold
- **Inputs**: `time_window_minutes` (int, default 30), `threshold` (int, default 5)
- **Implementation**: ES aggregation query — filter `outcome: "failure"`, aggregate by `source_ip` (terms agg), filter buckets with `min_doc_count` >= threshold. Return list of `{ip, count, earliest, latest}`.

### Tool 3: `get_event_details`
- **Purpose**: Retrieve full details of specific events
- **Inputs**: `event_ids` (list of strings) OR `source_ip` + `time_window_minutes` for a focused query
- **Implementation**: ES `mget` for IDs, or a targeted bool query for IP-based lookup. Return full event documents.

### Tool 4: `check_ip_reputation`
- **Purpose**: Query AbuseIPDB for threat intelligence on an IP
- **Inputs**: `ip_address` (string), `max_age_days` (int, default 90)
- **Implementation**: `GET https://api.abuseipdb.com/api/v2/check` with `Key` header. Return `{ip, abuse_confidence_score, country_code, isp, total_reports, last_reported_at, is_whitelisted}`.
- **Error handling**: Return structured error on rate limit (429) or network failure so Claude can reason about it.

### Tool 5: `create_incident_report`
- **Purpose**: Create a GitHub issue with formatted incident findings
- **Inputs**: `title` (string), `summary` (string), `affected_ips` (list), `attack_type` (string), `severity` (string: low/medium/high/critical), `recommendations` (list of strings)
- **Implementation**: `POST https://api.github.com/repos/{owner}/{repo}/issues` with Bearer token. Format the body as structured markdown with sections: Summary, Affected IPs (table), Threat Intelligence, Severity, Recommendations. Add labels: `["security-incident", severity]`.
- **Config**: GitHub repo (`owner/repo`) comes from CLI args or env var `GITHUB_REPO`.

### Module structure

```python
# Each tool has:
TOOL_SCHEMAS = [...]          # List of JSON schema dicts for Anthropic API
def execute_tool(name, input, es_client, config) -> str:  # Dispatcher
```

The `execute_tool` dispatcher takes the ES client and config as context (avoids globals), matches on tool name, calls the appropriate function, and returns a JSON string.

---

## Step 3: Create `src/agent.py` — Main Orchestrator

### 3a: Configuration

`Config` dataclass with fields:
- ES connection: `es_host`, `es_user`, `es_password`, `es_index`, `verify_certs`
- API keys: `anthropic_api_key`, `abuseipdb_api_key`, `github_token`
- Agent settings: `model` (default `claude-sonnet-4-5-20250929`), `max_iterations` (default 15), `github_repo`
- Watch mode: `watch` (bool), `poll_interval_seconds` (default 300)

Load from `.env` file via `python-dotenv`, then override with CLI args.

### 3b: CLI (argparse)

```
python3 src/agent.py \
  --es-host https://<host>:9200 \
  --es-password <password> \
  [--es-index security-logs] \
  [--no-verify-certs] \
  [--model claude-sonnet-4-5-20250929] \
  [--max-iterations 15] \
  [--github-repo owner/repo] \
  [--watch] \
  [--poll-interval 300] \
  [--debug]
```

### 3c: System Prompt

The system prompt tells Claude its role and the investigation pipeline:

```
You are a security incident response agent. You monitor Elasticsearch
security logs and investigate potential threats.

Your investigation pipeline:
1. DETECT — Use aggregate_failed_logins to find IPs with suspicious
   failure counts in the recent time window.
2. INVESTIGATE — For each suspicious IP, use search_security_logs and
   get_event_details to understand the attack pattern (timing, targeted
   users, auth methods, geo locations).
3. ENRICH — Use check_ip_reputation to get threat intelligence from
   AbuseIPDB for each suspicious IP.
4. CLASSIFY — Determine the attack type (brute_force, credential_stuffing,
   password_spraying, lateral_movement, impossible_travel) and severity.
5. REPORT — If threats are confirmed, use create_incident_report to file
   a GitHub issue with complete findings.

Always start with detection. If no suspicious activity is found, report
that the environment is clean. Do not create incident reports for benign
activity.
```

### 3d: Agentic Loop (manual, not tool_runner)

```python
def run_agent(config, es_client):
    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    messages = [{"role": "user", "content": f"Analyze the last 30 minutes of security logs in index '{config.es_index}' for threats. Investigate and report any incidents found."}]

    for iteration in range(config.max_iterations):
        response = client.messages.create(
            model=config.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages
        )

        # Log Claude's reasoning (text blocks)
        for block in response.content:
            if block.type == "text":
                logger.info(f"Agent: {block.text}")

        # If no tool calls, agent is done
        if response.stop_reason != "tool_use":
            break

        # Execute each tool call
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                logger.info(f"Tool call: {block.name}({json.dumps(block.input)})")
                result = execute_tool(block.name, block.input, es_client, config)
                logger.info(f"Tool result: {result[:200]}...")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result
                })

        # Append assistant response + tool results to conversation
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return messages  # Full conversation for debugging
```

### 3e: Watch Mode

When `--watch` is passed, wrap `run_agent` in a loop:

```python
while True:
    run_agent(config, es_client)
    logger.info(f"Sleeping {config.poll_interval_seconds}s...")
    time.sleep(config.poll_interval_seconds)
```

### 3f: Main entry point

1. Load `.env` via `dotenv.load_dotenv()`
2. Parse CLI args
3. Build `Config`
4. Create ES client (same pattern as `data_generator.py`)
5. Verify ES connectivity with `es.info()`
6. Run agent (once or in watch loop)

---

## Step 4: Set up `.env` and `.gitignore`

Populate `.env` with placeholder keys:

```
ANTHROPIC_API_KEY=
ABUSEIPDB_API_KEY=
GITHUB_TOKEN=
GITHUB_REPO=
```

Add `.env` to `.gitignore` if not already there.

---

## Step 5: Create `tests/conftest.py` — Shared Fixtures

Shared pytest fixtures used across test files:

- **`mock_config`** — Returns a `Config` dataclass with test values (dummy API keys, test index name, etc.)
- **`mock_es_client`** — Returns a `MagicMock` of the `Elasticsearch` client with pre-configured return values for `search()`, `mget()`, and `indices.exists()`
- **`sample_events`** — Returns a list of realistic `SecurityEvent` dicts matching the index schema (brute force pattern from a single IP, mix of success/failure)
- **`sample_aggregation_response`** — Returns a mock ES aggregation response with 2 suspicious IPs above threshold

---

## Step 6: Create `tests/test_tools.py` — Tool Unit Tests

All tests mock external dependencies (ES client, HTTP requests). No real ES or API calls.

### `search_security_logs` tests
- **`test_search_builds_correct_query`** — Verify the ES bool query includes the right `must` clauses when `source_ip`, `outcome`, and `username` are all provided. Assert `es.search()` is called with the expected query body.
- **`test_search_time_window`** — Verify the `range` filter on `timestamp` uses `now-{minutes}m/m` format.
- **`test_search_respects_max_results`** — Verify `size` parameter is passed to `es.search()`.
- **`test_search_no_filters`** — Verify that omitting all optional filters still produces a valid query (just time range).
- **`test_search_returns_json`** — Verify the return value is valid JSON containing the expected hit structure.

### `aggregate_failed_logins` tests
- **`test_aggregate_builds_terms_agg`** — Verify the query includes a `terms` aggregation on `source_ip` with `min_doc_count` matching the threshold.
- **`test_aggregate_filters_by_failure`** — Verify the query filters on `outcome: "failure"`.
- **`test_aggregate_returns_ip_list`** — Verify the return value is a JSON list of `{ip, count, earliest, latest}`.
- **`test_aggregate_empty_result`** — Verify graceful handling when no IPs exceed the threshold (returns empty list).

### `get_event_details` tests
- **`test_get_by_event_ids`** — Verify `es.mget()` is called with the provided IDs.
- **`test_get_by_source_ip`** — Verify fallback to a bool query when `source_ip` is provided instead of IDs.
- **`test_get_returns_full_documents`** — Verify all event fields are present in the returned JSON.

### `check_ip_reputation` tests (mock `requests.get`)
- **`test_reputation_success`** — Mock a 200 response from AbuseIPDB. Verify returned JSON contains `abuse_confidence_score`, `total_reports`, `country_code`.
- **`test_reputation_rate_limit`** — Mock a 429 response. Verify returns a structured error JSON with `"error"` key (not an exception).
- **`test_reputation_network_error`** — Mock a `requests.ConnectionError`. Verify returns structured error.

### `create_incident_report` tests (mock `requests.post`)
- **`test_report_creates_issue`** — Mock a 201 response from GitHub. Verify `requests.post` is called with correct URL, auth header, and body containing all sections (summary, affected IPs, severity, recommendations).
- **`test_report_labels`** — Verify the issue is created with `["security-incident", severity]` labels.
- **`test_report_api_error`** — Mock a 403 response. Verify returns structured error.

### `execute_tool` dispatcher tests
- **`test_dispatch_known_tool`** — Verify dispatching to each of the 5 tool names works.
- **`test_dispatch_unknown_tool`** — Verify an unknown tool name returns a JSON error (not an exception).

---

## Step 7: Create `tests/test_agent.py` — Agent Unit Tests

### Config tests
- **`test_config_defaults`** — Verify `Config()` has correct defaults (model, max_iterations, index, etc.).
- **`test_config_from_env`** — Set env vars, verify `Config` picks them up via `python-dotenv`.

### CLI parsing tests
- **`test_cli_required_args`** — Verify `--es-host` and `--es-password` are required.
- **`test_cli_defaults`** — Verify default values for optional args (`--es-index`, `--model`, `--max-iterations`, etc.).
- **`test_cli_watch_mode`** — Verify `--watch` and `--poll-interval` are parsed correctly.
- **`test_cli_no_verify_certs`** — Verify `--no-verify-certs` sets `verify_certs=False`.

### Agentic loop tests (mock `anthropic.Anthropic`)
- **`test_loop_stops_on_end_turn`** — Mock a response with `stop_reason="end_turn"` and no tool calls. Verify the loop exits after 1 iteration.
- **`test_loop_executes_tool_call`** — Mock a response with one `tool_use` block, then a second response with `stop_reason="end_turn"`. Verify `execute_tool` is called with the correct name and input, and the tool result is appended to messages.
- **`test_loop_handles_multiple_tool_calls`** — Mock a response with 2 `tool_use` blocks. Verify both are executed and both results sent back in a single user message.
- **`test_loop_respects_max_iterations`** — Mock responses that always return `tool_use`. Verify the loop stops after `max_iterations`.
- **`test_loop_message_structure`** — Verify the conversation messages alternate correctly: user → assistant (with tool_use) → user (with tool_result) → assistant → ...

---

## Step 8: Create `tests/test_integration.py` — ES Integration Tests

Integration tests for the 3 ES tools, running against a real Elasticsearch cluster. These validate that the actual queries, aggregations, and field mappings work end-to-end. External API tools (AbuseIPDB, GitHub) are **not** integration-tested — unit tests with mocks are sufficient for those.

All integration tests are marked with `@pytest.mark.integration` so they can be excluded from fast CI runs.

### Setup fixture: `es_test_index`

A session-scoped fixture that:
1. Connects to ES using env vars (`ES_HOST`, `ES_PASSWORD`) or defaults from `.env`
2. Creates a temporary test index (`test-security-logs-{uuid}`) with the same mapping from `data_generator.create_index_mapping()`
3. Seeds it with known test data: ~100 normal events + 1 brute force attack (50 failures from IP `185.220.101.42` against user `admin`) + 1 impossible travel event
4. Calls `es.indices.refresh()` to make data searchable immediately
5. Yields the ES client, index name, and known test data details
6. Tears down the index after all tests complete

### `search_security_logs` integration tests
- **`test_search_finds_failures`** — Search with `outcome="failure"`. Verify results contain the seeded brute force events.
- **`test_search_filters_by_ip`** — Search with `source_ip="185.220.101.42"`. Verify only events from that IP are returned.
- **`test_search_filters_by_username`** — Search with `username="admin"`. Verify results are scoped correctly.
- **`test_search_time_window_excludes_old`** — Seed an event with a timestamp 2 hours ago. Search with `time_window_minutes=30`. Verify the old event is excluded.
- **`test_search_max_results`** — Search with `max_results=5`. Verify exactly 5 results returned even though more exist.

### `aggregate_failed_logins` integration tests
- **`test_aggregate_detects_brute_force_ip`** — Aggregate with `threshold=10`. Verify the brute force IP (`185.220.101.42`) appears with count ~50.
- **`test_aggregate_threshold_filters`** — Aggregate with `threshold=100`. Verify the brute force IP is excluded (only ~50 failures).
- **`test_aggregate_returns_timestamps`** — Verify each returned bucket includes `earliest` and `latest` timestamps.

### `get_event_details` integration tests
- **`test_get_by_ids_returns_documents`** — Index a known event, retrieve it by ID. Verify all fields match.
- **`test_get_by_ip_returns_events`** — Retrieve events by `source_ip`. Verify results match the seeded data.

### Run commands

```bash
# Run unit tests only (no ES required)
pytest tests/ -v --ignore=tests/test_integration.py

# Run integration tests (requires running ES cluster)
pytest tests/test_integration.py -v

# Run all tests
pytest tests/ -v

# Run a single test
pytest tests/test_tools.py::test_search_builds_correct_query -v
```

---

## Verification

1. **Run unit tests**: `pytest tests/ -v --ignore=tests/test_integration.py` — all pass with no external dependencies
2. **Run integration tests**: `pytest tests/test_integration.py -v` — requires a running ES cluster (deploy with `./deployment/main.sh --all` first)
2. **Dry run**: Run the agent with `--debug` and inspect the logged tool calls and Claude's reasoning steps
3. **End-to-end**:
   - Generate data: `python3 src/data_generator.py --es-host ... --total 1000 --attack-probability 20`
   - Run agent: `python3 src/agent.py --es-host ... --es-password ... --no-verify-certs --debug`
   - Verify: Agent should detect suspicious IPs, enrich with AbuseIPDB, and create a GitHub issue
4. **Watch mode**: Run with `--watch --poll-interval 60` and feed data continuously to verify repeated detection cycles

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Agent loop | Manual (not `tool_runner`) | Full control over logging, retries, iteration limits |
| Model | Configurable via `--model`, default Sonnet | Balance cost/speed; override to Opus for complex cases |
| API keys | `.env` file + env var override | Convenient local dev; `.env` already exists in repo |
| Invocation | One-shot CLI + `--watch` flag | Start simple, add continuous polling without separate code |
| File split | `agent.py` + `tools.py` | Minimal separation; tools are reusable and testable independently |
| Framework | None (raw `anthropic` SDK) | Lightweight, no lock-in, transparent reasoning |
