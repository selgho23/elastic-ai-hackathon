# Elastic Incident Response Agent

## Overview

Build an AI-powered security incident response agent that detects threats in real-time from Elastic Stack data, enriches findings with threat intelligence, and automatically creates incident reports. The agent is built natively using Claude's tool_use API (with OpenAI as an alternative), talking directly to Elasticsearch — no Elastic AI Agent Builder required.

## Architecture

```
┌──────────────┐    ┌──────────────────┐    ┌───────────────────┐
│  Data         │    │  Elastic Stack   │    │  AI Agent         │
│  Generator    │───>│  (k3s/ECK)       │<───│  (Claude tool_use)│
│  (Python)     │    │  Elasticsearch   │    │                   │
│               │    │  Kibana          │    │  Tools:           │
│  5 attack     │    │                  │    │  - query ES       │
│  patterns     │    │  security-logs   │    │  - threat intel   │
│               │    │  index           │    │  - create report  │
└──────────────┘    └──────────────────┘    └───────────────────┘
```

## High-Level Steps

### Step 1: Deploy Elastic Stack to k3s
- Install ECK operator via Helm
- Deploy 2-node Elasticsearch cluster (4-8GB RAM, 5GB storage per node)
- Deploy Kibana with LoadBalancer access
- Expose Elasticsearch via LoadBalancer for external access
- Verify connectivity and credentials

### Step 2: Ingest Security Data
- Create `security-logs` index with proper mapping (keyword types, date, ip, geo)
- Generate streaming security log data with realistic attack patterns
- Simulate 5 attack types: brute force, credential stuffing, password spraying, lateral movement, impossible travel
- Interleave attacks with normal traffic for realistic data

### Step 3: Build AI Agent with Claude tool_use
- Build agent natively using Claude's tool_use API (no framework initially)
- Define tools the agent can call:
  - `search_security_logs` — query Elasticsearch for events matching criteria
  - `aggregate_by_ip` — find IPs exceeding failed login thresholds
  - `get_event_details` — retrieve full details of specific events
  - `summarize_attack_pattern` — analyse and describe detected patterns
- Implement multi-step reasoning: detect → investigate → classify → report

### Step 4: Build Elasticsearch Query Tool
- Create tool that queries failed login attempts
- Implement aggregation by source IP
- Add configurable time windows and thresholds
- Return suspicious IPs that exceed thresholds

### Step 5: Integrate Threat Intelligence
- Build tool to enrich IPs with AbuseIPDB API
- Fetch abuse confidence scores, country, report counts
- Handle API rate limits and errors gracefully

### Step 6: Build GitHub Integration
- Create tool to generate formatted incident reports
- Implement GitHub API integration to create issues
- Include all findings: IPs, threat intel, recommendations
- Add proper labels and formatting

### Step 7: Implement Alert Triggering
- Set up Elasticsearch Watcher or CronJob to detect anomalies
- Configure trigger conditions (threshold breaches)
- Connect trigger to agent invocation
- Agent runs investigation pipeline on each alert

### Step 8: Full Automation & Deployment
- Dockerize agent application
- Create Helm chart for agent deployment on k3s
- Build one-click deployment script
- Document the entire stack in code

### Step 9: Demo & Documentation
- Record video showing real-time detection
- Create architecture diagrams
- Write comprehensive documentation
- Prepare submission materials

## Quick Start

### 1. Install Tools

```bash
sudo ./environment/install_tools.sh --all
# Or pick specific tools:
sudo ./environment/install_tools.sh docker k3s helm jq python nodejs claude-code
```

Available tools: `docker`, `k3s`, `helm`, `jq`, `python` (3.12 from source), `nodejs`, `claude-code`

### 2. Deploy Elastic Stack

```bash
./deployment/main.sh --all           # Deploy full stack
./deployment/main.sh elk-access   # Show Elasticsearch + Kibana URLs and credentials
```

### 3. Generate Security Data

```bash
pip install -r src/requirements.txt
python src/data_generator.py \
  --es-host https://<es-host>:9200 \
  --es-password <password> \
  --no-verify-certs \
  --total 10000 \
  --rate 10.0 \
  --attack-probability 15.0
```

Use `--debug` to enable verbose logging and see bulk index error details.

Output modes: `elasticsearch` (default, bulk indexing), `stdout`, `file` (NDJSON).

### 4. Build & Run Agent (coming next)

```bash
# TODO: agent implementation
python src/agent.py --es-host https://<es-host>:9200 --es-password <password>
```

## Project Structure

```
environment/
  install_tools.sh      → Modular tool installer (docker, k3s, helm, jq, python, nodejs, claude-code)
deployment/
  main.sh               → Multi-step deployment orchestrator with interactive menu
  eck-operator.yaml     → Helm values for ECK operator
  eck-elasticsearch.yaml → Helm values for Elasticsearch (2-node, LoadBalancer)
  eck-kibana.yaml       → Helm values for Kibana (LoadBalancer)
src/
  data_generator.py     → Security log generator with 5 attack patterns
  requirements.txt      → Python dependencies
  agent.py              → AI incident response agent (TODO)
```

## Agent Approach

The agent is built **natively with Claude's tool_use API** rather than using a framework. Rationale:

- **Full control** over tool dispatch, memory, and orchestration
- **No framework lock-in** — can swap to OpenAI function calling or other models
- **Lightweight** — only the Anthropic SDK + elasticsearch client needed
- **Transparent** — every step of the agent's reasoning is visible and debuggable

If complexity grows (multi-agent coordination, complex state graphs), consider adding **LangGraph** or **CrewAI** on top.

### Alternative Approaches Considered

| Approach | Pros | Cons |
|----------|------|------|
| Claude tool_use (chosen) | Full control, lightweight, no lock-in | Build plumbing yourself |
| LangChain/LangGraph | Rich ecosystem, state management | Can be over-engineered |
| LlamaIndex | Strong retrieval focus | Less agentic |
| CrewAI | Multi-agent coordination | Extra abstraction layer |
| Azure AI Foundry | Enterprise-ready, model catalog | Platform lock-in, complex setup |
| Elastic AI Agent Builder | Native ES integration | Not available for this project |

## Success Criteria

- Agent detects incidents within 5 minutes of occurrence
- Successfully enriches with external threat intelligence
- Automatically creates GitHub issues with complete reports
- Entire stack deployable via single command
- Professional documentation and demo video

## Tech Stack

- **Bash** — infrastructure scripts (`set -euo pipefail` convention)
- **Python 3.12** — data generation, agent, Elasticsearch integration
- **Claude API** — AI agent reasoning and tool orchestration
- **Helm 3 / YAML** — Kubernetes resource definitions
- **Elasticsearch 8.x + Kibana** — log storage, search, and visualization
- **k3s** — lightweight Kubernetes on Linux
