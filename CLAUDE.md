# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI-powered security incident response agent that detects threats in real-time from Elastic Stack data, enriches findings with threat intelligence, and automatically creates incident reports as GitHub issues. The agent is built natively using Claude's `tool_use` API, talking directly to Elasticsearch — no framework required.

## Commands

### Environment Setup
```bash
sudo ./environment/install_tools.sh --all          # Install all dev tools
sudo ./environment/install_tools.sh docker k3s helm # Install specific tools
sudo ./environment/install_tools.sh --list          # List available tools
```
Available tools: `docker`, `k3s`, `helm`, `jq`, `python` (3.12 from source to /opt/python), `nodejs`, `claude-code`

### Elastic Stack Deployment
```bash
./deployment/main.sh --all       # Deploy full stack (namespace, context, helm-repo, eck-operator, elasticsearch, kibana)
./deployment/main.sh elk-access  # Show Elasticsearch/Kibana URLs and credentials
./deployment/main.sh teardown    # Remove all resources
./deployment/main.sh --list      # List available operations
```
`KUBECONFIG` defaults to `/etc/rancher/k3s/k3s.yaml`. Cluster names configurable via `ELASTICSEARCH_CLUSTER_NAME` and `KIBANA_NAME` env vars (default: `hackathon`).

### Data Generator
```bash
pip install -r src/requirements.txt
python3 src/data_generator.py \
  --es-host https://<es-host>:9200 \
  --es-user elastic \
  --es-password <password> \
  --no-verify-certs \
  --total 10000 --rate 10.0 --attack-probability 15.0
```
Output modes: `elasticsearch` (default, bulk indexing), `stdout`, `file` (NDJSON). Use `--debug` for verbose logging.

### Agent (in progress)
```bash
python3 src/agent.py --es-host https://<es-host>:9200 --es-password <password>
```

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

### Agent Design
The agent uses Claude's `tool_use` API directly (no LangChain/LangGraph) for full control over tool dispatch and transparency. Multi-step reasoning pipeline: **detect → investigate → classify → report**.

Planned agent tools:
- `search_security_logs` — query Elasticsearch for events matching criteria
- `aggregate_by_ip` — find IPs exceeding failed login thresholds
- `get_event_details` — retrieve full details of specific events
- `summarize_attack_pattern` — analyse and describe detected patterns
- AbuseIPDB enrichment — threat intelligence scoring
- GitHub issue creation — formatted incident reports

### Infrastructure
- **k3s** cluster with `elastic` namespace
- **ECK operator** manages Elasticsearch and Kibana via Helm charts
- 2-node Elasticsearch cluster (4-8Gi RAM, 5Gi storage per node), Kibana single instance
- Both services exposed via LoadBalancer

### Data Generator Attack Patterns
Injects configurable attack scenarios into normal auth traffic:
1. Brute Force — single IP hammering one user
2. Credential Stuffing — single IP trying many usernames
3. Password Spraying — many IPs trying common passwords
4. Lateral Movement — post-auth spread to internal hosts
5. Impossible Travel — same user from distant locations

## Tech Stack
- **Python 3.12** — agent, data generation, Elasticsearch integration (dataclasses, generators, type hints)
- **Claude API** (`tool_use`) — AI agent reasoning and tool orchestration
- **Bash** — infrastructure scripts (`set -euo pipefail` convention)
- **Helm 3 / YAML** — Kubernetes resource definitions
- **Elasticsearch 8.x + Kibana** — log storage, search, and visualization
- **k3s** — lightweight Kubernetes on Linux
