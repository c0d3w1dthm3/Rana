"""The open-core SEAM — now a real loader. Paid packs register here; the engine
never changes. A plugin is any importable module exposing:

    register(registry: dict) -> None      REQUIRED  — add check functions
    rule_dirs() -> list[Path]             optional  — ship rule files
    mapper() -> Mapper                    optional  — fill `maps_to` (attestation)

Discovery, in order:
  1. installed packages declaring an entry point in group "agentscan.plugins"
     (the production path: `pip install agentscan-redteam`)
  2. AGENTSCAN_PLUGINS="mod1,mod2" env var (dev / non-installed fallback)

register() mutates the engine's CHECKS dict IN PLACE — that is the whole trick:
the engine keeps iterating the same registry, oblivious to who filled it.
"""
from __future__ import annotations
import importlib
import os
from pathlib import Path
from typing import Protocol
from .model import Finding
from .engine import CHECKS


class Mapper(Protocol):
    def map(self, finding: Finding) -> list[str]:
        """Return compliance citations for a finding. OSS default: []."""
        ...


def _entry_point_modules() -> list:
    mods = []
    try:
        from importlib.metadata import entry_points
        try:
            eps = entry_points(group="agentscan.plugins")      # py3.10+ selectable
        except TypeError:
            eps = entry_points().get("agentscan.plugins", [])  # older API
        for ep in eps:
            try:
                mods.append(ep.load())
            except Exception:
                continue
    except Exception:
        pass
    return mods


def _env_modules() -> list:
    mods = []
    for name in filter(None, (n.strip() for n in os.environ.get("AGENTSCAN_PLUGINS", "").split(","))):
        try:
            mods.append(importlib.import_module(name))
        except Exception:
            continue
    return mods


def load_plugins() -> tuple[list[Path], "Mapper | None"]:
    """Discover plugins, register their checks into CHECKS, and return any extra
    rule directories and the first compliance mapper they provide."""
    seen = set()
    rule_dirs: list[Path] = []
    mapper: Mapper | None = None
    for mod in _entry_point_modules() + _env_modules():
        if mod in seen:
            continue
        seen.add(mod)
        reg = getattr(mod, "register", None)
        if callable(reg):
            reg(CHECKS)                       # <-- registers into the engine's registry, in place
        rd = getattr(mod, "rule_dirs", None)
        if callable(rd):
            rule_dirs.extend(Path(p) for p in rd())
        mp = getattr(mod, "mapper", None)
        if callable(mp) and mapper is None:
            mapper = mp()
    return rule_dirs, mapper


def apply_mapper(findings: list[Finding], mapper: "Mapper | None") -> list[Finding]:
    if mapper is None:
        return findings                       # free tier: maps_to stays [] as shipped
    for f in findings:
        f.maps_to = mapper.map(f)
    return findings
