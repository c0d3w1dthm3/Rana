"""Rule engine: load declarative rules, evaluate against a Target, emit Findings.

RULES ARE DATA, CHECKS ARE CODE. A rule names a `check` by key; the engine looks
it up in CHECKS and runs it. A check returns a list of items, each either:
  - a str  -> a location; the finding takes the RULE's severity (legacy path), or
  - a Hit  -> a location plus an OPTIONAL per-finding severity override + detail.
Both are supported, so every existing string-returning check keeps working while
new checks (e.g. the active corpus) can grade findings individually.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Callable
from .model import Target, Finding, Hit, Severity

Check = Callable[[Target, dict[str, Any]], list]
CHECKS: dict[str, Check] = {}


def check(name: str):
    def deco(fn: Check) -> Check:
        CHECKS[name] = fn
        return fn
    return deco


DANGEROUS_TOOLS = {"Bash", "Shell", "Exec", "WriteFile", "Edit"}

_BUILTIN_SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]


def _walk_strings(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj


# ---- mcp-trust --------------------------------------------------------------
@check("mcp_server_unpinned")
def _mcp_unpinned(t: Target, p: dict) -> list:
    out = []
    for s in t.mcp_servers:
        if not (s.get("version") or s.get("sha256") or s.get("integrity")):
            out.append(f"mcp_server:{s.get('name', '<unnamed>')}")
    return out


@check("mcp_insecure_transport")
def _mcp_insecure(t: Target, p: dict) -> list:
    return [f"mcp_server:{s.get('name', '<unnamed>')} (http://)"
            for s in t.mcp_servers if str(s.get("url", "")).startswith("http://")]


# ---- permissions ------------------------------------------------------------
@check("dangerous_tool_autoapproved")
def _dangerous_autoapprove(t: Target, p: dict) -> list:
    allow = t.settings.get("permissions", {}).get("allow", [])
    has_pretool = bool(t.hooks.get("PreToolUse"))
    out = []
    if any(a == "*" or a.strip().lower() == "all" for a in allow) and not has_pretool:
        out.append("permissions.allow:* (no PreToolUse gate)")
    for a in allow:
        if a in DANGEROUS_TOOLS and not has_pretool:
            out.append(f"permissions.allow:{a} (no PreToolUse gate)")
    return out


@check("wildcard_permission_present")
def _wildcard_present(t: Target, p: dict) -> list:
    allow = t.settings.get("permissions", {}).get("allow", [])
    if any(a == "*" or a.strip().lower() == "all" for a in allow):
        return ["permissions.allow:* (wildcard grant — prefer an explicit allowlist)"]
    return []


@check("no_deny_list")
def _no_deny(t: Target, p: dict) -> list:
    perms = t.settings.get("permissions", {})
    if perms.get("allow") and not perms.get("deny"):
        return ["permissions.deny:<empty> (no explicit denies)"]
    return []


# ---- hooks ------------------------------------------------------------------
@check("no_audit_logging")
def _no_audit_logging(t: Target, p: dict) -> list:
    return ["hooks.PostToolUse:<missing>"] if not t.hooks.get("PostToolUse") else []


@check("pretool_missing_dangerous_coverage")
def _pretool_coverage(t: Target, p: dict) -> list:
    allow = t.settings.get("permissions", {}).get("allow", [])
    dangerous = [a for a in allow if a in DANGEROUS_TOOLS]
    pre = t.hooks.get("PreToolUse", [])
    if not dangerous or not pre:
        return []
    covers_all = False
    matchers = set()
    for h in pre:
        m = str(h.get("matcher", ""))
        if m in ("*", ""):
            covers_all = True
        matchers.add(m)
    if covers_all:
        return []
    return [f"PreToolUse: no matcher covers '{a}'" for a in dangerous if a not in matchers]


# ---- prompt -----------------------------------------------------------------
@check("claude_md_missing")
def _claude_md_missing(t: Target, p: dict) -> list:
    return ["CLAUDE.md:<missing>"] if not t.claude_md else []


@check("risky_directive_in_claude_md")
def _risky_directive(t: Target, p: dict) -> list:
    text = t.claude_md or ""
    out = []
    for pat in p.get("patterns", []):
        try:
            if re.search(pat, text, re.IGNORECASE):
                out.append(f"CLAUDE.md: matches risky self-authored directive /{pat}/")
        except re.error:
            continue
    return out


# ---- memory -----------------------------------------------------------------
@check("env_embedded_in_config")
def _env_embedded(t: Target, p: dict) -> list:
    env = t.settings.get("env", {})
    return [f"settings.env.{k}" for k in env] if isinstance(env, dict) else []


# ---- secrets ----------------------------------------------------------------
@check("secret_in_config")
def _secret_in_config(t: Target, p: dict) -> list:
    compiled = []
    for pat in _BUILTIN_SECRET_PATTERNS + list(p.get("extra_patterns", [])):
        try:
            compiled.append(re.compile(pat))
        except re.error:
            pass
    out = []
    for loc, val in _walk_strings(t.settings):
        if any(c.search(val) for c in compiled):
            out.append(f"settings.{loc} (looks like a secret)")
    if t.claude_md and any(c.search(t.claude_md) for c in compiled):
        out.append("CLAUDE.md (looks like a secret)")
    return out


# ---- loading + evaluation ---------------------------------------------------
def _load_rule_file(path: Path) -> list:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError(f"{path.name} is YAML but PyYAML isn't installed.") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return data if isinstance(data, list) else [data]


def load_rules(rules_dir: Path) -> list:
    rules = []
    for path in sorted(Path(rules_dir).rglob("*")):
        if path.suffix in (".json", ".yaml", ".yml"):
            rules.extend(_load_rule_file(path))
    return rules


def _finding_from(rule: dict, item) -> Finding:
    rule_sev = Severity.parse(rule["severity"])
    rationale = rule["rationale"].strip()
    if isinstance(item, Hit):
        loc = item.location
        sev = item.severity if item.severity is not None else rule_sev
        if item.detail:
            rationale = f"{rationale} [{item.detail}]"
    else:                                  # legacy: bare location string
        loc = item
        sev = rule_sev
    return Finding(rule_id=rule["id"], name=rule["name"], severity=sev,
                   category=rule["category"], location=loc, rationale=rationale,
                   remediation=rule["remediation"].strip(), maps_to=list(rule.get("maps_to", [])))


def evaluate(target: Target, rules: list) -> list[Finding]:
    findings: list[Finding] = []
    for r in rules:
        fn = CHECKS.get(r["check"])
        if fn is None:
            continue
        for item in fn(target, r.get("params", {})):
            findings.append(_finding_from(r, item))
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings
