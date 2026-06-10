"""agentscan — deterministic static security posture scanner for agentic AI stacks.

OSS core: parses Claude Code / MCP / agent config and runs declarative rules.
No LLM, no network, zero third-party dependencies — by design (a security tool
should minimize its own attack surface). Active LLM-driven red-teaming and
compliance mapping attach as paid plugins via `plugins.py`.
"""
__version__ = "0.0.1"
