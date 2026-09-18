from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from . import __version__

from .models import Event

LOG = logging.getLogger("spamhaus_reporter.cloudflare")

QUERY = r"""
query FirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        filter: $filter
        limit: $limit
        orderBy: [datetime_ASC]
      ) {
        action
        clientAsn
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestPath
        clientRequestQuery
        datetime
        source
        userAgent
      }
    }
  }
}
"""


class CloudflareError(RuntimeError):
    pass


def _clean_text(value: object, *, max_len: int) -> str:
    # Remove control characters including terminal escapes/newlines. Keep
    # Unicode in storage, but ensure logs/reasons cannot be control-injected.
    text = str(value or "")
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return text[:max_len]


class CloudflareClient:
    def __init__(
        self,
        token: str,
        graphql_url: str,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.graphql_url = graphql_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"cloudflare-abuse-reporter/{__version__}",
            }
        )

    def _request_read_query(self, payload: dict[str, Any]) -> requests.Response:
        # GraphQL uses POST transport, but this operation is read-only and safe
        # to retry on transport failures / throttling / transient 5xx responses.
        retryable = {429, 500, 502, 503, 504}
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.post(self.graphql_url, json=payload, timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt >= self.max_retries:
                    raise CloudflareError(f"Cloudflare request failed: {exc}") from exc
                time.sleep(min(2**attempt, 8))
                continue
            if resp.status_code not in retryable or attempt >= self.max_retries:
                return resp
            retry_after = resp.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else float(2**attempt)
            except ValueError:
                delay = float(2**attempt)
            time.sleep(min(max(delay, 0.0), 30.0))
        raise CloudflareError("Cloudflare request failed")

    def _fetch_once(
        self,
        *,
        zone_name: str,
        zone_id: str,
        start: datetime,
        end: datetime,
        limit: int,
        actions: list[str],
    ) -> list[Event]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("start/end must be timezone-aware")
        if start >= end:
            return []

        filter_obj: dict[str, Any] = {
            "datetime_geq": start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "datetime_leq": end.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        if len(actions) == 1:
            filter_obj["action"] = actions[0]
        elif actions:
            filter_obj["action_in"] = actions

        payload = {
            "query": QUERY,
            "variables": {"zoneTag": zone_id, "filter": filter_obj, "limit": int(limit)},
        }
        resp = self._request_read_query(payload)
        if resp.status_code != 200:
            raise CloudflareError(f"Cloudflare HTTP {resp.status_code}: {resp.text[:1000]}")

        try:
            body = resp.json()
        except ValueError as exc:
            raise CloudflareError("Cloudflare returned non-JSON response") from exc
        if body.get("errors"):
            raise CloudflareError(f"Cloudflare GraphQL error: {body['errors']}")

        zones = (((body.get("data") or {}).get("viewer") or {}).get("zones") or [])
        if len(zones) != 1:
            raise CloudflareError(
                f"Expected exactly one Cloudflare zone for {zone_name} ({zone_id}); got {len(zones)}"
            )
        rows = zones[0].get("firewallEventsAdaptive") or []
        if not isinstance(rows, list):
            raise CloudflareError("Cloudflare firewallEventsAdaptive response is not a list")

        out: list[Event] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            dt_raw = str(row.get("datetime") or "")
            try:
                dt = datetime.fromisoformat(dt_raw.replace("Z", "+00:00"))
            except ValueError:
                LOG.warning("Skipping Cloudflare event with invalid datetime: %r", dt_raw)
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)

            ip = str(row.get("clientIP") or "").strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                LOG.warning("Skipping Cloudflare event with invalid client IP: %r", ip)
                continue

            host = _clean_text(row.get("clientRequestHTTPHost") or zone_name, max_len=253).lower()
            path = _clean_text(row.get("clientRequestPath") or "/", max_len=4096) or "/"
            query = _clean_text(row.get("clientRequestQuery") or "", max_len=4096)
            ua = _clean_text(row.get("userAgent") or "", max_len=2048)
            country = _clean_text(row.get("clientCountryName") or "", max_len=128)
            source = _clean_text(row.get("source") or "", max_len=128)
            action = _clean_text(row.get("action") or "", max_len=64)
            try:
                asn = int(row["clientAsn"]) if row.get("clientAsn") is not None else None
            except (TypeError, ValueError):
                asn = None

            out.append(
                Event(
                    zone=zone_name,
                    zone_id=zone_id,
                    host=host,
                    client_ip=ip,
                    path=path,
                    query=query,
                    action=action,
                    source=source,
                    user_agent=ua,
                    country=country,
                    asn=asn,
                    observed_at=dt,
                )
            )
        return out

    def fetch_events(
        self,
        *,
        zone_name: str,
        zone_id: str,
        start: datetime,
        end: datetime,
        limit: int,
        actions: list[str],
        _depth: int = 0,
    ) -> list[Event]:
        """Fetch a range and recursively split saturated result windows."""
        rows = self._fetch_once(
            zone_name=zone_name,
            zone_id=zone_id,
            start=start,
            end=end,
            limit=limit,
            actions=actions,
        )
        if len(rows) < limit:
            return rows

        duration = (end - start).total_seconds()
        if duration <= 1 or _depth >= 24:
            raise CloudflareError(
                f"Cloudflare query for {zone_name} is saturated at {limit} events "
                f"even for a {duration:.3f}s window; refusing to silently drop evidence."
            )
        midpoint = start + (end - start) / 2
        left = self.fetch_events(
            zone_name=zone_name, zone_id=zone_id, start=start, end=midpoint,
            limit=limit, actions=actions, _depth=_depth + 1,
        )
        right = self.fetch_events(
            zone_name=zone_name, zone_id=zone_id, start=midpoint, end=end,
            limit=limit, actions=actions, _depth=_depth + 1,
        )
        return left + right
