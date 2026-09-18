from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable

from .models import Candidate, Finding, unique_preserve_order


CATEGORY_ORDER = [
    "traversal_lfi",
    "webshell",
    "cloud_credentials",
    "secrets_config",
    "source_control",
    "db_admin",
    "backup_dump",
    "wordpress",
    "api_debug",
    "admin_login",
    "directory_enum",
]

# Patterns are intentionally biased toward reconnaissance of commonly sensitive
# locations. A match alone does not imply compromise or malicious intent.
PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "wordpress": [
        re.compile(r"(?:^|/)wp-login\.php(?:$|[/?])", re.I),
        re.compile(r"(?:^|/)xmlrpc\.php(?:$|[/?])", re.I),
        re.compile(r"(?:^|/)wp-admin(?:/|$)", re.I),
        re.compile(r"(?:^|/)wp-includes(?:/|$)", re.I),
        re.compile(r"(?:^|/)wp-content(?:/|$)", re.I),
        re.compile(r"wlwmanifest\.xml(?:$|[?])", re.I),
    ],
    "secrets_config": [
        re.compile(r"(?:^|/)\.env(?:\.|/|$)", re.I),
        re.compile(r"(?:^|/)(?:key|keys|secret|secrets|credentials|config|configuration)\.(?:json|ya?ml|ini|toml)(?:$|[?])", re.I),
        re.compile(r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:$|[.?/])", re.I),
        re.compile(r"(?:^|/)\.npmrc(?:$|[?])", re.I),
        re.compile(r"(?:^|/)\.ssh(?:/|$)", re.I),
    ],
    "source_control": [
        re.compile(r"(?:^|/)\.git(?:/|$)", re.I),
        re.compile(r"(?:^|/)\.svn(?:/|$)", re.I),
        re.compile(r"(?:^|/)\.hg(?:/|$)", re.I),
        re.compile(r"(?:^|/)\.bzr(?:/|$)", re.I),
    ],
    "db_admin": [
        re.compile(r"(?:^|/)(?:phpmyadmin|phpMyAdmin|pma)(?:/|$)", re.I),
        re.compile(r"(?:^|/)adminer(?:\.php|/|$)", re.I),
        re.compile(r"(?:^|/)(?:mysql|mysqladmin)(?:/|$)", re.I),
    ],
    "backup_dump": [
        re.compile(r"(?:^|/)[^/?]+\.(?:sql|sqlite|sqlite3|bak|old|orig|backup|dump)(?:$|[?])", re.I),
        re.compile(r"(?:^|/)(?:backup|backups|dump|dumps)(?:/|$)", re.I),
        re.compile(r"(?:^|/)[^/?]+\.(?:zip|tar|tgz|tar\.gz|7z|rar)(?:$|[?])", re.I),
    ],
    "cloud_credentials": [
        re.compile(r"(?:^|/)\.aws/credentials(?:$|[?])", re.I),
        re.compile(r"(?:^|/)service[-_]?account\.json(?:$|[?])", re.I),
        re.compile(r"(?:^|/)amplifyconfiguration\.json(?:$|[?])", re.I),
        re.compile(r"(?:^|/)firebase\.json(?:$|[?])", re.I),
        re.compile(r"(?:^|/)google[-_]?services\.json(?:$|[?])", re.I),
        re.compile(r"(?:^|/)azure.*credentials", re.I),
    ],
    "api_debug": [
        re.compile(r"(?:^|/)(?:swagger(?:-ui)?|api-docs)(?:/|$)", re.I),
        re.compile(r"(?:^|/)openapi\.(?:json|ya?ml)(?:$|[?])", re.I),
        re.compile(r"(?:^|/)actuator(?:/|$)", re.I),
        re.compile(r"(?:^|/)debug(?:/|$)", re.I),
        re.compile(r"(?:^|/)graphql(?:/|$)", re.I),
        re.compile(r"(?:^|/)server-status(?:$|[/?])", re.I),
        re.compile(r"(?:^|/)server-info(?:$|[/?])", re.I),
        re.compile(r"(?:^|/)phpinfo(?:\.php)?(?:$|[/?])", re.I),
        re.compile(r"(?:^|/)vendor/phpunit(?:/|$)", re.I),
    ],
    "webshell": [
        re.compile(r"(?:^|/)(?:wso|alfa|shell|cmd|c99|r57|b374k|filesman)\.php(?:$|[?])", re.I),
        re.compile(r"(?:^|/)wp-content/.*(?:shell|wso|alfa|cmd).*\.php(?:$|[?])", re.I),
    ],
    "traversal_lfi": [
        re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c))", re.I),
        re.compile(r"(?:^|/)(?:etc/passwd|etc/shadow|proc/self/environ)(?:$|[?])", re.I),
        re.compile(r"(?:^|/)(?:windows/)?win\.ini(?:$|[?])", re.I),
    ],
    "admin_login": [
        re.compile(r"^/(?:admin|administrator|login|signin|cpanel)(?:/|$)", re.I),
        re.compile(r"^/manager/html(?:/|$)", re.I),
        re.compile(r"^/(?:admin|administrator)/(?:login|signin)(?:/|$)", re.I),
    ],
}


CATEGORY_LABELS = {
    "wordpress": "WordPress/CMS reconnaissance",
    "secrets_config": "sensitive configuration-file probing",
    "source_control": "source-control metadata probing",
    "db_admin": "database-admin interface probing",
    "backup_dump": "backup/database-dump probing",
    "cloud_credentials": "cloud credential/config probing",
    "api_debug": "API/debug endpoint reconnaissance",
    "webshell": "web-shell/backdoor reconnaissance",
    "traversal_lfi": "path-traversal/local-file probing",
    "admin_login": "admin/login endpoint enumeration",
    "directory_enum": "high-volume directory/endpoint enumeration",
    "generic_scan": "broad automated reconnaissance",
}


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Keep path semantics but collapse accidental double slashes for matching.
    path = path.split("#", 1)[0]
    if "?" in path:
        path = path.split("?", 1)[0]
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path
    return path


def classify_path(path: str) -> set[str]:
    p = normalize_path(path)
    matched: set[str] = set()
    for category, patterns in PATTERNS.items():
        if any(rx.search(p) for rx in patterns):
            matched.add(category)
    return matched


def ip_is_allowlisted(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _score(findings: list[Finding], request_count: int, duration_seconds: float) -> int:
    if not findings:
        return 0
    score = 25
    unique_suspicious = len({p for f in findings for p in f.matched_paths})
    score += min(unique_suspicious * 4, 36)
    score += min(max(len(findings) - 1, 0) * 7, 21)
    if request_count >= 10:
        score += 5
    if request_count >= 20:
        score += 5
    if duration_seconds <= 10 and request_count >= 4:
        score += 8
    return min(score, 99)


def _primary(findings: list[Finding]) -> str:
    by_name = {f.category: f for f in findings}
    for category in CATEGORY_ORDER:
        if category in by_name:
            return category
    return findings[0].category if findings else "generic_scan"


def _reason_safe(value: object, max_len: int = 220) -> str:
    # Spamhaus reason is capped at 255. Keep it deterministic ASCII and strip
    # control characters so hostile Host/path values cannot inject formatting.
    text = str(value or "")
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)
    text = " ".join(text.split())
    return text[:max_len]


def _path_summary(paths: list[str], max_chars: int) -> str:
    shown: list[str] = []
    used = 0
    for p in paths:
        p = _reason_safe(normalize_path(p), 180)
        addition = (", " if shown else "") + p
        if used + len(addition) > max_chars:
            break
        shown.append(p)
        used += len(addition)
    return ", ".join(shown)


def make_reason(
    *, host: str, category: str, paths: list[str], unique_count: int, request_count: int
) -> str:
    label = CATEGORY_LABELS.get(category, "automated web reconnaissance")
    host = _reason_safe(host, 120)
    prefix = f"Observed {label} against {host}. "
    suffix = f" {unique_count} unique suspicious paths/{request_count} blocked requests in a short window; Cloudflare security logs under my control."
    available = 255 - len(prefix) - len(suffix) - len("Paths: ")
    path_text = _path_summary(paths, max(0, available))
    if path_text:
        reason = prefix + "Paths: " + path_text + "." + suffix
    else:
        reason = prefix + suffix.lstrip()
    if len(reason) <= 255 and len(reason.encode("utf-8")) <= 255:
        return reason

    # Deterministic fallback with no path list.
    reason = (
        f"Observed {label} against {host}: {unique_count} unique suspicious paths / "
        f"{request_count} blocked requests in a short window. Evidence from Cloudflare security logs under my control."
    )
    return reason[:255]


def build_candidate(rows: list[Any], config: dict[str, Any]) -> Candidate | None:
    if not rows:
        return None

    rows = sorted(rows, key=lambda r: str(r["observed_at"]))
    ip = str(rows[0]["client_ip"])
    allowlist = config.get("allowlist_cidrs") or []
    if ip_is_allowlisted(ip, allowlist):
        return None

    allowed_asns = {int(x) for x in (config.get("allowlist_asns") or [])}
    row_asns = {int(r["asn"]) for r in rows if r["asn"] is not None}
    if allowed_asns and row_asns and row_asns.issubset(allowed_asns):
        return None

    ua_patterns = [
        re.compile(str(x), re.I) for x in (config.get("allowlist_user_agent_regexes") or [])
    ]
    if ua_patterns:
        uas = [str(r["user_agent"]) for r in rows if r["user_agent"]]
        if uas and all(any(rx.search(ua) for rx in ua_patterns) for ua in uas):
            return None

    paths = unique_preserve_order(normalize_path(str(r["path"])) for r in rows)
    category_paths: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        for cat in classify_path(p):
            category_paths[cat].append(p)

    findings = [
        Finding(category=cat, matched_paths=vals, unique_count=len(set(vals)))
        for cat, vals in category_paths.items()
    ]
    findings.sort(key=lambda f: CATEGORY_ORDER.index(f.category) if f.category in CATEGORY_ORDER else 999)

    first = datetime.fromisoformat(str(rows[0]["observed_at"]))
    last = datetime.fromisoformat(str(rows[-1]["observed_at"]))
    duration = max((last - first).total_seconds(), 0.0)
    request_count = len(rows)
    unique_suspicious = len({p for f in findings for p in f.matched_paths})

    thresholds = config.get("thresholds") or {}
    ready_categories = {
        f.category
        for f in findings
        if f.unique_count >= int(thresholds.get(f.category, 10**9))
    }

    min_generic_paths = int(thresholds.get("generic_scan", 15))
    min_generic_categories = int(config.get("generic_scan_min_categories", 2))
    min_generic_requests = int(config.get("generic_scan_min_total_requests", 20))
    generic_ready = (
        unique_suspicious >= min_generic_paths
        and len(findings) >= min_generic_categories
        and request_count >= min_generic_requests
    )

    # Catch true directory brute-forcing that does not happen to hit one of the
    # named technology patterns. This is intentionally high-threshold and is
    # review-only by default in config.yaml to limit false positives.
    directory_min_paths = int(config.get("directory_enum_min_unique_paths", 30))
    directory_min_requests = int(config.get("directory_enum_min_total_requests", 40))
    directory_max_seconds = int(config.get("directory_enum_max_window_seconds", 600))
    directory_ready = (
        len(paths) >= directory_min_paths
        and request_count >= directory_min_requests
        and duration <= directory_max_seconds
    )

    if ready_categories:
        status = "READY"
    elif generic_ready:
        status = "READY"
        findings.append(
            Finding(
                category="generic_scan",
                matched_paths=unique_preserve_order(p for f in findings for p in f.matched_paths),
                unique_count=unique_suspicious,
            )
        )
    elif directory_ready:
        status = "READY"
        findings.append(
            Finding(category="directory_enum", matched_paths=paths, unique_count=len(paths))
        )
    elif findings:
        status = "REVIEW"
    else:
        status = "IGNORE"

    if ready_categories:
        ready_findings = [f for f in findings if f.category in ready_categories]
        ready_findings.sort(
            key=lambda f: (
                -f.unique_count,
                CATEGORY_ORDER.index(f.category) if f.category in CATEGORY_ORDER else 999,
            )
        )
        primary = ready_findings[0].category
    else:
        primary = _primary(findings)
    # If only generic condition made it ready, describe the broad scan.
    if generic_ready and not ready_categories:
        primary = "generic_scan"
    elif directory_ready and not ready_categories and not generic_ready:
        primary = "directory_enum"

    host_counts = Counter(str(r["host"]) for r in rows if r["host"])
    host = host_counts.most_common(1)[0][0] if host_counts else str(rows[0]["zone"])
    reason = make_reason(
        host=host,
        category=primary,
        paths=unique_preserve_order(
            p for f in findings if f.category != "generic_scan" for p in f.matched_paths
        ),
        unique_count=unique_suspicious,
        request_count=request_count,
    )

    return Candidate(
        ip=ip,
        host=host,
        zone=str(rows[0]["zone"]),
        first_seen=first,
        last_seen=last,
        request_count=request_count,
        unique_paths=paths,
        findings=findings,
        status=status,
        primary_category=primary,
        confidence=_score(findings, request_count, duration),
        reason=reason,
        countries=unique_preserve_order(str(r["country"]) for r in rows if r["country"]),
        asns=unique_preserve_order(int(r["asn"]) for r in rows if r["asn"] is not None),
        sources=unique_preserve_order(str(r["source"]) for r in rows if r["source"]),
        user_agents=unique_preserve_order(str(r["user_agent"]) for r in rows if r["user_agent"]),
    )


def candidates_from_rows(rows: list[Any], config: dict[str, Any]) -> list[Candidate]:
    # Group by IP and then by rolling aggregation window. This prevents events
    # from unrelated times of day from inflating the threshold.
    window_minutes = int(config.get("aggregation_window_minutes", 10))
    max_gap = window_minutes * 60
    by_ip_zone: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for row in rows:
        by_ip_zone[(str(row["client_ip"]), str(row["zone"]))].append(row)

    candidates: list[Candidate] = []
    for ip_rows in by_ip_zone.values():
        ip_rows.sort(key=lambda r: str(r["observed_at"]))
        cluster: list[Any] = []
        cluster_start: datetime | None = None
        for row in ip_rows:
            cur = datetime.fromisoformat(str(row["observed_at"]))
            if cluster_start is not None and (cur - cluster_start).total_seconds() > max_gap:
                cand = build_candidate(cluster, config)
                if cand:
                    candidates.append(cand)
                cluster = []
                cluster_start = None
            if cluster_start is None:
                cluster_start = cur
            cluster.append(row)
        if cluster:
            cand = build_candidate(cluster, config)
            if cand:
                candidates.append(cand)

    return sorted(candidates, key=lambda c: (c.status != "READY", -c.confidence, c.ip))
