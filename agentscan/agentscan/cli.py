"""CLI entry point. Run: python3 -m agentscan scan <path> [--active] [--format ...] [--fail-on ...]"""
from __future__ import annotations
import argparse
from pathlib import Path
from . import __version__
from . import plugins
from .collect import collect_claude_code
from .engine import load_rules, evaluate
from .report import render
from .model import Severity

_RULES_DIR = Path(__file__).parent / "rules"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentscan",
        description="Static security posture scanner for agentic AI stacks.")
    ap.add_argument("command", choices=["scan"])
    ap.add_argument("path", nargs="?", default="~/.claude",
                    help="agent config root to scan (default: ~/.claude)")
    ap.add_argument("--active", action="store_true",
                    help="also run active LLM-driven probes from installed paid packs "
                         "(opt-in: needs a configured model and makes live calls)")
    ap.add_argument("--format", choices=["tty", "json", "sarif"], default="tty",
                    help="output format (default: tty)")
    ap.add_argument("--out", help="write output to a file instead of stdout")
    ap.add_argument("--rules", default=str(_RULES_DIR),
                    help="rules directory (default: built-in OSS rules)")
    ap.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                    help="exit non-zero if any finding meets/exceeds this severity (CI gate)")
    ap.add_argument("--version", action="version", version=f"agentscan {__version__}")
    args = ap.parse_args(argv)

    target = collect_claude_code(Path(args.path))
    if not target.recognized:
        print(f"no recognizable agent config under {target.root} — nothing to scan "
              f"(looked for settings.json, .mcp.json, CLAUDE.md)")
        return 0

    # Installed paid packs register checks into the engine's CHECKS and may add
    # rule dirs + a compliance mapper. No packs -> behaviour identical to free.
    extra_rule_dirs, mapper = plugins.load_plugins()
    rules = load_rules(Path(args.rules))
    for d in extra_rule_dirs:
        rules += load_rules(d)

    # Active probes are opt-in. Default scan runs static rules only — fast, free,
    # no model needed — even when an active pack is installed. (Filter lives here,
    # NOT in the engine: engine.py never learns the difference.)
    if not args.active:
        rules = [r for r in rules if r.get("mode", "static") != "active"]

    findings = evaluate(target, rules)            # same engine call, free + paid alike
    findings = plugins.apply_mapper(findings, mapper)

    output = render(findings, args.format)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"wrote {len(findings)} finding(s) -> {args.out}")
    else:
        print(output)

    if args.fail_on and findings and max(f.severity for f in findings) >= Severity.parse(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
