from __future__ import annotations

import time
from typing import Any

import requests

from . import __version__


class AbuseIPDBError(RuntimeError):
    pass


class AbuseIPDBAmbiguousSubmissionError(AbuseIPDBError):
    """POST outcome is unknown; an automatic retry could duplicate a report."""


class AbuseIPDBClient:
    """Small, conservative AbuseIPDB API v2 client.

    GET requests may be retried because they are idempotent. REPORT POST requests
    are deliberately attempted exactly once; a transport failure is treated as
    ambiguous so the caller can back off instead of blindly duplicating a report.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.abuseipdb.com/api/v2",
        timeout: int = 30,
        max_get_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_get_retries = max_get_retries
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": f"cloudflare-abuse-reporter/{__version__}",
            }
        )

    @staticmethod
    def _json(resp: requests.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text[:4000]}

    def _get(self, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        retryable = {429, 500, 502, 503, 504}
        for attempt in range(self.max_get_retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                if attempt >= self.max_get_retries:
                    raise AbuseIPDBError(f"AbuseIPDB GET failed: {exc}") from exc
                time.sleep(min(2**attempt, 8))
                continue
            if resp.status_code not in retryable or attempt >= self.max_get_retries:
                return resp
            retry_after = resp.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else float(2**attempt)
            except ValueError:
                delay = float(2**attempt)
            time.sleep(min(max(delay, 0.0), 30.0))
        raise AbuseIPDBError("AbuseIPDB GET failed")

    def check_auth(self) -> dict[str, Any]:
        """Validate the API key with the read-only CHECK endpoint.

        This proves API authentication without creating a report. AbuseIPDB
        reporting privilege is still ultimately exercised by the first real
        REPORT request.
        """
        resp = self._get(
            "check",
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
        )
        data = self._json(resp)
        if resp.status_code != 200:
            raise AbuseIPDBError(
                f"AbuseIPDB auth check failed HTTP {resp.status_code}: {str(data)[:1200]}"
            )
        if not isinstance(data, dict):
            raise AbuseIPDBError(f"Unexpected AbuseIPDB check response: {data!r}")
        return data

    def submit_ip_once(
        self,
        *,
        ip: str,
        categories: list[int],
        comment: str,
        timestamp: str,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        """Perform exactly one AbuseIPDB REPORT POST, never an automatic retry."""
        if not categories:
            raise ValueError("At least one AbuseIPDB category is required")
        if any(not isinstance(x, int) or x < 1 or x > 23 for x in categories):
            raise ValueError("AbuseIPDB category IDs must be integers between 1 and 23")
        if len(comment.encode("utf-8")) > 1024:
            raise ValueError("AbuseIPDB comment exceeds 1024 bytes")

        url = f"{self.base_url}/report"
        payload = {
            "ip": ip,
            "categories": ",".join(str(x) for x in sorted(set(categories))),
            "comment": comment,
            "timestamp": timestamp,
        }
        try:
            resp = self.session.post(url, timeout=self.timeout, data=payload)
        except requests.RequestException as exc:
            raise AbuseIPDBAmbiguousSubmissionError(
                f"AbuseIPDB POST outcome unknown for {ip}: {exc}"
            ) from exc

        body = self._json(resp)
        if not isinstance(body, dict):
            body = {"data": body}
        headers = {
            key: value
            for key, value in resp.headers.items()
            if key.lower() in {
                "retry-after",
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
            }
        }
        return resp.status_code, body, headers
