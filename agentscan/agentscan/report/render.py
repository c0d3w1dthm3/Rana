"""Render findings as human-readable TTY, machine JSON, or SARIF 2.1.0.

SARIF is here on purpose: it's the format GitHub code-scanning and most security
tooling already ingest, so agentscan slots into pipelines people already run.
"""
from __future__ import annotations
import json
from ..model import Finding, Severity

_ICON = {Severity.CRITICAL: "x", Severity.HIGH: "x", Severity.MEDIUM: "!",
         Severity.LOW: "-", Severity.INFO: "."}


def _tty(findings: list[Finding]) -> str:
    if not findings:
        return "OK  no findings"
    lines = []
    for f in findings:
        lines.append(f"{_ICON.get(f.severity, '-')} [{str(f.severity).upper()}] {f.rule_id}  {f.name}")
        lines.append(f"    where: {f.location}")
        lines.append(f"    why:   {f.rationale}")
        lines.append(f"    fix:   {f.remediation}")
        if f.maps_to:
            lines.append(f"    maps:  {', '.join(f.maps_to)}")
        lines.append("")
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def _json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def _sarif(findings: list[Finding]) -> str:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
             Severity.LOW: "note", Severity.INFO: "note"}
    rules_seen: dict[str, dict] = {}
    results = []
    for f in findings:
        rules_seen.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.name,
            "shortDescription": {"text": f.name},
            "fullDescription": {"text": f.rationale},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": level.get(f.severity, "warning"),
            "message": {"text": f"{f.rationale} | fix: {f.remediation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location}}}],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "agentscan", "rules": list(rules_seen.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def render(findings: list[Finding], fmt: str) -> str:
    return {"tty": _tty, "json": _json, "sarif": _sarif}[fmt](findings)
