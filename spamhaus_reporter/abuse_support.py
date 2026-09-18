from __future__ import annotations

from typing import Any

from .classifier import CATEGORY_LABELS, normalize_path
from .models import Candidate


DEFAULT_CATEGORY_MAP: dict[str, list[int]] = {
    # AbuseIPDB category 21 = Web App Attack. Category 15 = Hacking.
    # Keep the default mapping conservative and specific; operators may override
    # it in config when they have stronger evidence for another category.
    "wordpress": [21],
    "secrets_config": [21],
    "source_control": [21],
    "db_admin": [21],
    "backup_dump": [21],
    "cloud_credentials": [21],
    "api_debug": [21],
    "webshell": [15, 21],
    "traversal_lfi": [15, 21],
    "admin_login": [21],
    "generic_scan": [21],
    "directory_enum": [21],
}


def _ascii_clean(value: object, max_chars: int) -> str:
    text = str(value or "")
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)
    text = " ".join(text.split())
    return text[:max_chars]


def categories_for_candidate(candidate: Candidate, category_map: dict[str, Any] | None = None) -> list[int]:
    mapping = dict(DEFAULT_CATEGORY_MAP)
    for key, value in (category_map or {}).items():
        if isinstance(value, list) and value:
            mapping[str(key)] = [int(x) for x in value]
    return sorted(set(mapping.get(candidate.primary_category, [21])))


def make_comment(candidate: Candidate, *, max_bytes: int = 1024) -> str:
    """Build a concise, PII-minimized AbuseIPDB comment from observed evidence."""
    label = CATEGORY_LABELS.get(candidate.primary_category, "automated web reconnaissance")
    host = _ascii_clean(candidate.host, 160)
    paths: list[str] = []
    suspicious_paths = [p for finding in candidate.findings for p in finding.matched_paths]
    for path in suspicious_paths:
        cleaned = _ascii_clean(normalize_path(path), 220)
        if cleaned and cleaned not in paths:
            paths.append(cleaned)
        if len(paths) >= 8:
            break

    prefix = f"Observed {label} against {host}. "
    suffix = (
        f" {candidate.request_count} blocked requests in a short window. "
        "Observed directly in Cloudflare Security Events on infrastructure under my control."
    )
    body = "Representative paths: " + ", ".join(paths) + "." if paths else ""
    text = _ascii_clean(prefix + body + suffix, max_bytes)

    # ASCII cleaning makes chars == bytes, but keep a byte-oriented guard.
    while len(text.encode("utf-8")) > max_bytes:
        text = text[:-1]
    return text
