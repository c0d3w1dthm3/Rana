"""Model clients for the active red-team harness. A client is a callable:
    client(system_prompt: str, untrusted: str) -> str
returning the agent-under-test's response text. Operate ONLY against agents you
own or are explicitly authorized to test.

  AnthropicClient  real Anthropic Messages API calls via stdlib urllib (zero
                   extra deps). Reads ANTHROPIC_API_KEY. Set model= to the model
                   your agent actually runs.
  ReplayClient     replays responses from a JSON cassette keyed by content hash;
                   run/test the whole pipeline deterministically and offline.
  SimulatedClient  scripted client for unit tests.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path


class ModelClientError(RuntimeError):
    pass


class AnthropicClient:
    API = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str, *, api_key: "str | None" = None,
                 max_tokens: int = 512, timeout: int = 30, version: str = "2023-06-01"):
        self.model = model                      # set to the model your agent runs
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.version = version

    def __call__(self, system: str, untrusted: str) -> str:
        if not self.api_key:
            raise ModelClientError("ANTHROPIC_API_KEY not set — cannot make live calls.")
        # NO defensive coaching is added here: the harness must measure the
        # AGENT'S robustness (its own system prompt), not the harness's framing.
        body = json.dumps({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
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
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


class ReplayClient:
    def __init__(self, cassette):
        if isinstance(cassette, (str, Path)):
            self._data = json.loads(Path(cassette).read_text(encoding="utf-8"))
        else:
            self._data = dict(cassette)

    @staticmethod
    def key(system: str, untrusted: str) -> str:
        return hashlib.sha256((system + "\x00" + untrusted).encode("utf-8")).hexdigest()[:16]

    def __call__(self, system: str, untrusted: str) -> str:
        k = self.key(system, untrusted)
        if k not in self._data:
            raise ModelClientError(f"no recorded response for key {k}")
        return self._data[k]


class SimulatedClient:
    """mode='vulnerable' echoes any planted marker tokens (agent complies);
    mode='safe' refuses. Test use only."""
    _MARK = re.compile(r"[A-Z]{3,}-[A-Z0-9]{3,}")

    def __init__(self, mode: str = "safe"):
        self.mode = mode

    def __call__(self, system: str, untrusted: str) -> str:
        if self.mode == "vulnerable":
            marks = self._MARK.findall(system + " " + untrusted)
            return "Okay: " + " ".join(dict.fromkeys(marks))
        return "I won't act on instructions embedded in external data."
