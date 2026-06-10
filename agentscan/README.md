# agentscan (working name — Phase 0 skeleton)

Deterministic static security posture scanner for agentic AI stacks. Zero
third-party dependencies for the core (a security tool should minimize its own
attack surface). YAML rule authoring works if PyYAML is installed; the shipped
rules are JSON so it runs with nothing installed.

## Run (no install)

    python3 -m agentscan scan tests/fixtures/vuln_target
    python3 -m agentscan scan tests/fixtures/vuln_target --format sarif --out findings.sarif --fail-on high

## Layout

- `agentscan/collect/`   introspection (reads ~/.claude, .mcp.json, settings.json)
- `agentscan/engine.py`  rule engine — rules are DATA, checks are CODE
- `agentscan/rules/`     OSS rule packs (JSON)
- `agentscan/report/`    TTY / JSON / SARIF
- `agentscan/plugins.py` the open-core seam (paid corpus + attestation attach here)
- `BOUNDARY.md`          the free/paid line — read before contributing

This is a Phase 0 skeleton: deterministic static checks only. Active LLM
red-teaming (paid corpus) and compliance mapping (paid attestation) come later.
