#!/usr/bin/env python3
"""
AI Incident Response Agent
Detects security incidents from Elasticsearch data, enriches with threat
intelligence (AbuseIPDB), and creates GitHub issues.
Uses Claude's tool_use API with a manual agentic loop.
"""

import argparse
import json
import logging
import os
import time
import warnings
from dataclasses import dataclass

import anthropic
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from tools import TOOL_SCHEMAS, execute_tool

warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Agent configuration — loaded from .env then overridden by CLI args."""
    # Elasticsearch
    es_host: str = "https://localhost:9200"
    es_user: str = "elastic"
    es_password: str = ""
    es_index: str = "security-logs"
    verify_certs: bool = False

    # API keys
    anthropic_api_key: str = ""
    abuseipdb_api_key: str = ""
    github_token: str = ""

    # Agent settings
    model: str = "claude-sonnet-4-5-20250929"
    max_iterations: int = 15
    github_repo: str = ""

    # Watch mode
    watch: bool = False
    poll_interval_seconds: int = 300

    debug: bool = False


# =============================================================================
# System Prompt
# =============================================================================

SYSTEM_PROMPT = """\
You are a security incident response agent. You monitor Elasticsearch \
security logs and investigate potential threats.

Your investigation pipeline:
1. DETECT — Use aggregate_failed_logins to find IPs with suspicious \
failure counts in the recent time window.
2. INVESTIGATE — For each suspicious IP, use search_security_logs and \
get_event_details to understand the attack pattern (timing, targeted \
users, auth methods, geo locations).
3. ENRICH — Use check_ip_reputation to get threat intelligence from \
AbuseIPDB for each suspicious IP.
4. CLASSIFY — Determine the attack type (brute_force, credential_stuffing, \
password_spraying, lateral_movement, impossible_travel) and severity.
5. REPORT — If threats are confirmed, use create_incident_report to file \
a GitHub issue with complete findings.

Always start with detection. If no suspicious activity is found, report \
that the environment is clean. Do not create incident reports for benign \
activity.\
"""


# =============================================================================
# Agentic Loop
# =============================================================================

def run_agent(config: Config, es_client: Elasticsearch) -> list:
    """Run one investigation cycle. Returns the full message history."""
    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    messages = [
        {
            "role": "user",
            "content": (
                f"Analyze the last 30 minutes of security logs in index "
                f"'{config.es_index}' for threats. Investigate and report "
                f"any incidents found."
            ),
        }
    ]

    for iteration in range(config.max_iterations):
        logger.info(f"--- Iteration {iteration + 1}/{config.max_iterations} ---")

        response = client.messages.create(
            model=config.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        # Log Claude's reasoning
        for block in response.content:
            if hasattr(block, "text"):
                logger.info(f"Agent: {block.text}")

        # If no tool calls, agent is done
        if response.stop_reason != "tool_use":
            logger.info("Agent finished (no more tool calls).")
            break

        # Execute each tool call
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                logger.info(f"Tool call: {block.name}({json.dumps(block.input)})")
                result = execute_tool(block.name, block.input, es_client, config)
                logger.info(f"Tool result: {result[:500]}...")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    }
                )

        # Append assistant response + tool results
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return messages


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Incident Response Agent — detects, investigates, and reports security threats"
    )
    parser.add_argument("--es-host", default=None, help="Elasticsearch host URL")
    parser.add_argument("--es-user", default=None, help="Elasticsearch username")
    parser.add_argument("--es-password", default=None, help="Elasticsearch password")
    parser.add_argument("--es-index", default=None, help="Elasticsearch index name")
    parser.add_argument("--no-verify-certs", action="store_true", help="Disable TLS cert verification")
    parser.add_argument("--model", default=None, help="Claude model ID (default: claude-sonnet-4-5-20250929)")
    parser.add_argument("--max-iterations", type=int, default=None, help="Max agentic loop iterations")
    parser.add_argument("--github-repo", default=None, help="GitHub repo for incident reports (owner/repo)")
    parser.add_argument("--watch", action="store_true", help="Run continuously, polling on an interval")
    parser.add_argument("--poll-interval", type=int, default=None, help="Seconds between watch cycles (default: 300)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    """Build Config from .env defaults, then override with CLI args."""
    config = Config(
        es_host=os.getenv("ES_HOST", Config.es_host),
        es_user=os.getenv("ES_USER", Config.es_user),
        es_password=os.getenv("ES_PASSWORD", Config.es_password),
        es_index=os.getenv("ES_INDEX", Config.es_index),
        verify_certs=True,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        model=os.getenv("MODEL", Config.model),
        github_repo=os.getenv("GITHUB_REPO", ""),
    )

    # CLI overrides
    if args.es_host is not None:
        config.es_host = args.es_host
    if args.es_user is not None:
        config.es_user = args.es_user
    if args.es_password is not None:
        config.es_password = args.es_password
    if args.es_index is not None:
        config.es_index = args.es_index
    if args.no_verify_certs:
        config.verify_certs = False
    if args.model is not None:
        config.model = args.model
    if args.max_iterations is not None:
        config.max_iterations = args.max_iterations
    if args.github_repo is not None:
        config.github_repo = args.github_repo
    if args.watch:
        config.watch = True
    if args.poll_interval is not None:
        config.poll_interval_seconds = args.poll_interval
    if args.debug:
        config.debug = True

    return config


# =============================================================================
# Main
# =============================================================================

def main():
    load_dotenv()
    args = parse_args()
    config = build_config(args)

    # Set up logging
    log_level = logging.DEBUG if config.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Validate required config
    if not config.anthropic_api_key:
        logger.error("ANTHROPIC_API_KEY is required (set in .env or environment).")
        return
    if not config.es_password:
        logger.error("Elasticsearch password is required (--es-password or ES_PASSWORD).")
        return

    # Connect to Elasticsearch
    logger.info(f"Connecting to Elasticsearch at {config.es_host}...")
    es_client = Elasticsearch(
        config.es_host,
        basic_auth=(config.es_user, config.es_password),
        verify_certs=config.verify_certs,
    )

    # Verify connectivity
    try:
        info = es_client.info()
        logger.info(f"Connected to Elasticsearch {info['version']['number']}")
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        return

    # Run agent
    logger.info(f"Starting agent (model={config.model}, index={config.es_index})")
    if config.watch:
        logger.info(f"Watch mode: polling every {config.poll_interval_seconds}s")
        while True:
            try:
                run_agent(config, es_client)
            except Exception:
                logger.exception("Agent cycle failed")
            logger.info(f"Sleeping {config.poll_interval_seconds}s...")
            time.sleep(config.poll_interval_seconds)
    else:
        run_agent(config, es_client)
        logger.info("Agent run complete.")


if __name__ == "__main__":
    main()
