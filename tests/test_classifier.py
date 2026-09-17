from datetime import datetime, timezone

from spamhaus_reporter.classifier import candidates_from_rows, make_reason


CFG = {
    "aggregation_window_minutes": 10,
    "thresholds": {
        "wordpress": 4,
        "secrets_config": 3,
        "source_control": 2,
        "db_admin": 3,
        "backup_dump": 3,
        "cloud_credentials": 2,
        "api_debug": 4,
        "webshell": 2,
        "traversal_lfi": 2,
        "admin_login": 6,
        "generic_scan": 15,
    },
    "generic_scan_min_categories": 2,
    "generic_scan_min_total_requests": 20,
    "allowlist_cidrs": ["127.0.0.0/8", "10.0.0.0/8"],
}


def row(ip: str, path: str, *, zone="example.com", host="www.example.com", second=0):
    return {
        "client_ip": ip,
        "zone": zone,
        "host": host,
        "path": path,
        "observed_at": datetime(2026, 9, 17, 0, 55, second, tzinfo=timezone.utc).isoformat(),
        "country": "France",
        "asn": 60068,
        "source": "firewallcustom",
        "user_agent": "Mozilla/5.0",
    }


def test_wordpress_example_is_ready():
    rows = [
        row("203.0.113.40", "/blog/wp-includes/wlwmanifest.xml"),
        row("203.0.113.40", "/cms/wp-includes/wlwmanifest.xml"),
        row("203.0.113.40", "/web/wp-includes/wlwmanifest.xml"),
        row("203.0.113.40", "/xmlrpc.php"),
    ]
    c = candidates_from_rows(rows, CFG)[0]
    assert c.status == "READY"
    assert c.primary_category == "wordpress"
    assert "WordPress" in c.reason
    assert len(c.reason) <= 255


def test_sensitive_config_example_is_ready():
    rows = [
        row("203.0.113.41", "/key.json"),
        row("203.0.113.41", "/amplifyconfiguration.json"),
        row("203.0.113.41", "/service-account.json"),
        row("203.0.113.41", "/app/.env"),
        row("203.0.113.41", "/.env.old"),
        row("203.0.113.41", "/public/.env"),
    ]
    c = candidates_from_rows(rows, CFG)[0]
    assert c.status == "READY"
    assert c.primary_category == "secrets_config"
    assert len(c.reason) <= 255


def test_single_wp_login_is_review_not_ready():
    c = candidates_from_rows([row("203.0.113.25", "/wp-login.php")], CFG)[0]
    assert c.status == "REVIEW"


def test_private_ip_is_ignored_entirely():
    assert candidates_from_rows([row("10.1.2.3", "/.env")], CFG) == []


def test_reason_is_capped():
    reason = make_reason(
        host="very-long-hostname.example.com",
        category="secrets_config",
        paths=["/" + ("x" * 100) + str(i) for i in range(20)],
        unique_count=20,
        request_count=50,
    )
    assert len(reason) <= 255


def test_high_volume_unknown_directory_enumeration_is_ready_review_class():
    rows = [
        row("203.0.113.99", f"/random-path-{i}", second=min(i, 59))
        for i in range(40)
    ]
    cfg = dict(CFG)
    cfg.update({
        "directory_enum_min_unique_paths": 30,
        "directory_enum_min_total_requests": 40,
        "directory_enum_max_window_seconds": 600,
    })
    c = candidates_from_rows(rows, cfg)[0]
    assert c.status == "READY"
    assert c.primary_category == "directory_enum"
    assert len(c.reason) <= 255
