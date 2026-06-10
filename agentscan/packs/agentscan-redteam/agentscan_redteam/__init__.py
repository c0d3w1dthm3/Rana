"""agentscan-redteam — PAID active red-team pack.

Runs a CORPUS of probes against the agent-under-test via the plugin seam. The
shipped corpus is canonical, well-known basics; the real product is a
continuously-updated proprietary corpus. Operate ONLY against agents you own or
are explicitly authorized to test.

Wiring a live model client (production):
    from agentscan_redteam import configure
    from agentscan_redteam.clients import AnthropicClient
    configure(AnthropicClient(model="<the model your agent runs>"))  # reads ANTHROPIC_API_KEY
Then:  agentscan scan <path> --active
"""
from __future__ import annotations
from pathlib import Path
from agentscan.model import Finding
from . import corpus

_MODEL = None


def configure(model_client) -> None:
    """Inject the model client used to exercise the agent-under-test."""
    global _MODEL
    _MODEL = model_client


def _resolve_model():
    if _MODEL is not None:
        return _MODEL
    raise RuntimeError("agentscan-redteam: no model client configured — call "
                       "configure(AnthropicClient(...)). Active probes need a live agent.")


def _corpus_active(target, params) -> list:
    return corpus.run(_resolve_model(), target, params)


# compliance mapper — illustrative control IDs ONLY, not verified legal mappings.
_MAP = {
    "secrets": ["HIPAA 164.312(a)(1) (illustrative)", "SOC2 CC6.1 (illustrative)"],
    "hooks": ["HIPAA 164.312(b) audit controls (illustrative)"],
    "prompt": ["NIST AI RMF MEASURE-2.7 (illustrative)"],
    "mcp-trust": ["SOC2 CC6.6 (illustrative)"],
    "permissions": ["HIPAA 164.312(a)(1) least privilege (illustrative)"],
    "memory": ["HIPAA 164.312(e)(1) (illustrative)"],
}


class _CitationMapper:
    def map(self, finding: Finding) -> list:
        return _MAP.get(finding.category, [])


def register(registry: dict) -> None:
    registry["corpus_active_probe"] = _corpus_active


def rule_dirs():
    return [Path(__file__).parent / "rules"]


def mapper():
    return _CitationMapper()
