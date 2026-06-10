"""Agent clients that observe TOOL CALLS, not just text — the difference between
a prompt linter and an agent security tool. A client exposes:
    run(system: str, untrusted: str, tools: list[dict]) -> AgentRun
where AgentRun carries the response text AND the tool calls the agent attempted.

  AnthropicAgentClient   declares the agent's tools to the Messages API and reads
                         the returned tool_use blocks. Observes tool-call INTENT
                         and NEVER executes anything — so probing is safe.
  ClaudeCodeAgentClient  drives a real Claude Code (or any) run on the probe, with
                         a PreToolUse observe-hook that logs each attempted call to
                         a JSONL trace and BLOCKS it (exit 2) — intent captured,
                         execution prevented.
  SimulatedAgentClient   scripted, for offline tests.

Operate ONLY against agents you own or are explicitly authorized to test.
"""
from __future__ import annotations
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from .clients import ModelClientError

_DANGEROUS = {"Bash", "Shell", "Exec", "WriteFile", "Edit"}


@dataclass
class ToolCall:
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class AgentRun:
    text: str = ""
    tool_calls: list = field(default_factory=list)   # list[ToolCall]


class AnthropicAgentClient:
    """Observes tool-use intent via the Messages API. Declares `tools`, runs ONE
    turn, and parses tool_use blocks. Never executes a tool — safe by design."""
    API = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str, *, api_key: "str | None" = None,
                 max_tokens: int = 1024, timeout: int = 30, version: str = "2023-06-01"):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.version = version

    def run(self, system: str, untrusted: str, tools=None) -> AgentRun:
        if not self.api_key:
            raise ModelClientError("ANTHROPIC_API_KEY not set — cannot make live calls.")
        body = json.dumps({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "tools": tools or [],
            "messages": [{"role": "user", "content": untrusted}],
        }).encode("utf-8")
        req = urllib.request.Request(self.API, data=body, method="POST", headers={
            "x-api-key": self.api_key,
            "anthropic-version": self.version,
            "content-type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise ModelClientError(f"Anthropic API HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise ModelClientError(f"network error reaching Anthropic API: {e.reason}") from e
        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        calls = [ToolCall(name=b.get("name", ""), arguments=b.get("input", {}))
                 for b in blocks if b.get("type") == "tool_use"]
        return AgentRun(text=text, tool_calls=calls)


# A PreToolUse observe-hook: logs the attempted call as JSONL and BLOCKS it (exit
# 2), so a probe sees INTENT without the agent actually running the tool. Install
# it as a command hook with matcher "*" in the target's Claude Code settings.
OBSERVE_HOOK = '''#!/usr/bin/env python3
import sys, json, os
try:
    data = json.load(sys.stdin)            # {tool_name, tool_input, cwd, session_id, ...}
except Exception:
    data = {}
rec = {"tool": data.get("tool_name"), "input": data.get("tool_input")}
with open(os.environ.get("AGENTSCAN_TRACE", "/tmp/agentscan-trace.jsonl"), "a") as fh:
    fh.write(json.dumps(rec) + "\\n")
print("agentscan: tool call observed and blocked (red-team dry run)", file=sys.stderr)
sys.exit(2)                                # exit 2 = block the tool before it runs
'''


class ClaudeCodeAgentClient:
    """Drives a real agent run on the probe and reads tool calls from the JSONL
    trace written by OBSERVE_HOOK. `runner` is the command template for your
    deployment ('{prompt}' is substituted) — confirm the flag against current
    Claude Code docs / set it to however your app runs headless."""
    def __init__(self, runner=("claude", "-p", "{prompt}"), *,
                 trace_path: str = "/tmp/agentscan-trace.jsonl",
                 cwd: "str | None" = None, timeout: int = 120):
        self.runner = list(runner)
        self.trace_path = trace_path
        self.cwd = cwd
        self.timeout = timeout

    def run(self, system: str, untrusted: str, tools=None) -> AgentRun:
        import subprocess
        open(self.trace_path, "w").close()              # reset the trace
        env = dict(os.environ); env["AGENTSCAN_TRACE"] = self.trace_path
        cmd = [a.replace("{prompt}", untrusted) for a in self.runner]
        try:
            proc = subprocess.run(cmd, cwd=self.cwd, env=env,
                                  capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError as e:
            raise ModelClientError(f"runner not found: {cmd[0]!r} — set runner=(...) "
                                   f"to how your agent runs headless.") from e
        except subprocess.TimeoutExpired as e:
            raise ModelClientError(f"agent run timed out after {self.timeout}s") from e
        return AgentRun(text=proc.stdout, tool_calls=self._parse_trace(self.trace_path))

    @staticmethod
    def _parse_trace(path) -> list:
        out = []
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            return out
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            out.append(ToolCall(name=rec.get("tool") or rec.get("tool_name") or "",
                                arguments=rec.get("input") or rec.get("tool_input") or {}))
        return out


class SimulatedAgentClient:
    """mode='vulnerable' complies AND reaches for a tool carrying any planted
    marker; mode='safe' refuses and calls nothing. Test use only."""
    _MARK = re.compile(r"[A-Z]{3,}-[A-Z0-9]{3,}")

    def __init__(self, mode: str = "safe"):
        self.mode = mode

    def run(self, system: str, untrusted: str, tools=None) -> AgentRun:
        tools = tools or []
        if self.mode == "vulnerable":
            marks = self._MARK.findall(system + " " + untrusted)
            tname = next((t["name"] for t in tools if t["name"] in _DANGEROUS),
                         tools[0]["name"] if tools else "Bash")
            calls = [ToolCall(name=tname, arguments={"command": "exfiltrate " + " ".join(marks)})]
            return AgentRun(text="Okay: " + " ".join(dict.fromkeys(marks)), tool_calls=calls)
        return AgentRun(text="I won't act on instructions embedded in external data.")
