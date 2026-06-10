"""Introspection for Claude Code / MCP stacks.

Net-new vs. Karen: Karen audited ONE known target; the scanner must discover an
arbitrary one. Best-effort and defensive — a missing/malformed file yields an
empty section, never a crash, because we scan untrusted / unknown layouts.
"""
from __future__ import annotations
import json
from pathlib import Path
from ..model import Target


def _load_json(path: Path) -> tuple[dict, bool]:
    """Return (parsed, existed). A malformed file counts as existed (so we still
    flag it as a recognized-but-broken target rather than 'nothing here')."""
    if not path.exists():
        return {}, False
    try:
        return json.loads(path.read_text(encoding="utf-8")), True
    except (json.JSONDecodeError, OSError):
        return {}, True


def collect_claude_code(root: Path) -> Target:
    root = Path(root).expanduser()
    settings, s_ok = _load_json(root / "settings.json")
    mcp_doc, m_ok = _load_json(root / ".mcp.json")

    servers_map = {**mcp_doc.get("mcpServers", {}), **settings.get("mcpServers", {})}
    mcp_servers = [{"name": name, **cfg} for name, cfg in servers_map.items()]
    hooks = {event: list(hlist) for event, hlist in settings.get("hooks", {}).items()}

    claude_md_path = root / "CLAUDE.md"
    c_ok = claude_md_path.exists()
    claude_md = claude_md_path.read_text(encoding="utf-8") if c_ok else None

    return Target(root=root, recognized=(s_ok or m_ok or c_ok), claude_md=claude_md,
                  settings=settings, mcp_servers=mcp_servers, hooks=hooks)
