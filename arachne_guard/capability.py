"""Capability tags: ``domain.action[:qualifier]`` with glob-style matching."""
from __future__ import annotations

import re
from fnmatch import fnmatchcase

Capability = str

_CAP_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+(:[A-Za-z0-9_.\-]+)?$")
_PATTERN_RE = re.compile(r"^[A-Za-z0-9_.:\-*]+$")


def validate_capability(value: str) -> str:
    """Return ``value`` if it is a concrete capability, else raise ValueError."""
    if not isinstance(value, str) or not _CAP_RE.match(value):
        raise ValueError(f"capability {value!r} must match 'domain.action[:qualifier]'")
    return value


def validate_pattern(value: str) -> str:
    """Validate a capability pattern (may contain ``*`` wildcards)."""
    if not isinstance(value, str) or not value or not _PATTERN_RE.match(value):
        raise ValueError(f"invalid capability pattern {value!r}")
    return value


def matches(pattern: str, capability: str) -> bool:
    """True if ``capability`` is matched by ``pattern`` (case-sensitive glob)."""
    return fnmatchcase(capability, pattern)
