"""Unit tests for agent.py — Config, CLI parsing, and agentic loop."""

import json
import os
from unittest.mock import MagicMock, patch, call
from types import SimpleNamespace

import pytest

from agent import Config, parse_args, build_config, run_agent, SYSTEM_PROMPT


# =============================================================================
# Config tests
# =============================================================================

class TestConfig:
    def test_config_defaults(self):
        """Verify Config() has correct defaults."""
        config = Config()
        assert config.model == "claude-sonnet-4-5-20250929"
        assert config.max_iterations == 15
        assert config.es_index == "security-logs"
        assert config.es_user == "elastic"
        assert config.verify_certs is False
        assert config.watch is False
        assert config.poll_interval_seconds == 300

    def test_config_from_env(self, monkeypatch):
        """Verify build_config picks up environment variables."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
        monkeypatch.setenv("ES_HOST", "https://es-from-env:9200")
        monkeypatch.setenv("GITHUB_REPO", "envowner/envrepo")

        args = SimpleNamespace(
            es_host=None, es_user=None, es_password=None, es_index=None,
            no_verify_certs=False, model=None, max_iterations=None,
            github_repo=None, watch=False, poll_interval=None, debug=False,
        )
        config = build_config(args)

        assert config.anthropic_api_key == "sk-from-env"
        assert config.es_host == "https://es-from-env:9200"
        assert config.github_repo == "envowner/envrepo"


# =============================================================================
# CLI parsing tests
# =============================================================================

class TestCLI:
    def test_cli_required_args(self):
        """Verify --es-host and --es-password are not required at parse time
        (they're validated later in main)."""
        # parse_args with no args should work (defaults are None)
        with patch("sys.argv", ["agent.py"]):
            args = parse_args()
            assert args.es_host is None
            assert args.es_password is None

    def test_cli_defaults(self):
        """Verify default values for optional args."""
        with patch("sys.argv", ["agent.py"]):
            args = parse_args()
            assert args.es_index is None
            assert args.model is None
            assert args.max_iterations is None
            assert args.watch is False
            assert args.debug is False

    def test_cli_watch_mode(self):
        """Verify --watch and --poll-interval are parsed correctly."""
        with patch("sys.argv", ["agent.py", "--watch", "--poll-interval", "60"]):
            args = parse_args()
            assert args.watch is True
            assert args.poll_interval == 60

    def test_cli_no_verify_certs(self):
        """Verify --no-verify-certs flag."""
        with patch("sys.argv", ["agent.py", "--no-verify-certs"]):
            args = parse_args()
            assert args.no_verify_certs is True

        # Build config and verify it takes effect
        args_ns = SimpleNamespace(
            es_host=None, es_user=None, es_password=None, es_index=None,
            no_verify_certs=True, model=None, max_iterations=None,
            github_repo=None, watch=False, poll_interval=None, debug=False,
        )
        config = build_config(args_ns)
        assert config.verify_certs is False


# =============================================================================
# Agentic loop tests
# =============================================================================

def _make_text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _make_tool_use_block(tool_id, name, tool_input):
    block = MagicMock()
    block.type = "tool_use"
    block.id = tool_id
    block.name = name
    block.input = tool_input
    return block


class TestAgenticLoop:
    @patch("agent.execute_tool")
    @patch("agent.anthropic.Anthropic")
    def test_loop_stops_on_end_turn(self, mock_anthropic_cls, mock_execute, mock_config, mock_es_client):
        """Agent should exit after 1 iteration when stop_reason is end_turn."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        response = MagicMock()
        response.stop_reason = "end_turn"
        response.content = [_make_text_block("No threats found.")]
        mock_client.messages.create.return_value = response

        messages = run_agent(mock_config, mock_es_client)

        mock_client.messages.create.assert_called_once()
        mock_execute.assert_not_called()

    @patch("agent.execute_tool", return_value='{"result": "ok"}')
    @patch("agent.anthropic.Anthropic")
    def test_loop_executes_tool_call(self, mock_anthropic_cls, mock_execute, mock_config, mock_es_client):
        """Agent should execute tool and continue when stop_reason is tool_use."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        # First response: tool call
        resp1 = MagicMock()
        resp1.stop_reason = "tool_use"
        resp1.content = [
            _make_text_block("Detecting threats..."),
            _make_tool_use_block("toolu_1", "aggregate_failed_logins", {"threshold": 5}),
        ]

        # Second response: done
        resp2 = MagicMock()
        resp2.stop_reason = "end_turn"
        resp2.content = [_make_text_block("Environment is clean.")]

        mock_client.messages.create.side_effect = [resp1, resp2]

        messages = run_agent(mock_config, mock_es_client)

        mock_execute.assert_called_once_with(
            "aggregate_failed_logins", {"threshold": 5}, mock_es_client, mock_config
        )
        assert mock_client.messages.create.call_count == 2

    @patch("agent.execute_tool", return_value='{"result": "ok"}')
    @patch("agent.anthropic.Anthropic")
    def test_loop_handles_multiple_tool_calls(self, mock_anthropic_cls, mock_execute, mock_config, mock_es_client):
        """Agent should execute all tool calls in a single response and send all results."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        # Response with 2 tool calls
        resp1 = MagicMock()
        resp1.stop_reason = "tool_use"
        resp1.content = [
            _make_tool_use_block("toolu_1", "search_security_logs", {"source_ip": "1.2.3.4"}),
            _make_tool_use_block("toolu_2", "check_ip_reputation", {"ip_address": "1.2.3.4"}),
        ]

        resp2 = MagicMock()
        resp2.stop_reason = "end_turn"
        resp2.content = [_make_text_block("Done.")]

        mock_client.messages.create.side_effect = [resp1, resp2]

        messages = run_agent(mock_config, mock_es_client)

        assert mock_execute.call_count == 2

    @patch("agent.execute_tool", return_value='{"result": "ok"}')
    @patch("agent.anthropic.Anthropic")
    def test_loop_respects_max_iterations(self, mock_anthropic_cls, mock_execute, mock_config, mock_es_client):
        """Loop should stop after max_iterations even if tool calls keep coming."""
        mock_config.max_iterations = 3
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        # Every response triggers another tool call
        resp = MagicMock()
        resp.stop_reason = "tool_use"
        resp.content = [
            _make_tool_use_block("toolu_x", "aggregate_failed_logins", {}),
        ]
        mock_client.messages.create.return_value = resp

        messages = run_agent(mock_config, mock_es_client)

        assert mock_client.messages.create.call_count == 3

    @patch("agent.execute_tool", return_value='{"events": []}')
    @patch("agent.anthropic.Anthropic")
    def test_loop_message_structure(self, mock_anthropic_cls, mock_execute, mock_config, mock_es_client):
        """Verify messages alternate: user → assistant (tool_use) → user (tool_result) → ..."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        resp1 = MagicMock()
        resp1.stop_reason = "tool_use"
        resp1.content = [
            _make_tool_use_block("toolu_1", "aggregate_failed_logins", {}),
        ]

        resp2 = MagicMock()
        resp2.stop_reason = "end_turn"
        resp2.content = [_make_text_block("Clean.")]

        mock_client.messages.create.side_effect = [resp1, resp2]

        messages = run_agent(mock_config, mock_es_client)

        # messages[0] = initial user message
        assert messages[0]["role"] == "user"
        # messages[1] = assistant with tool_use content
        assert messages[1]["role"] == "assistant"
        # messages[2] = user with tool_result
        assert messages[2]["role"] == "user"
        assert messages[2]["content"][0]["type"] == "tool_result"
        assert messages[2]["content"][0]["tool_use_id"] == "toolu_1"
