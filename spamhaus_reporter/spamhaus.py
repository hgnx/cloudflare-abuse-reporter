from __future__ import annotations

import time
from typing import Any

import requests

from . import __version__


class SpamhausError(RuntimeError):
    pass


class SpamhausAmbiguousSubmissionError(SpamhausError):
    """POST outcome is unknown; an automatic retry could duplicate a report."""


class SpamhausClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        timeout: int = 30,
        max_get_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_get_retries = max_get_retries
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": f"cloudflare-abuse-reporter/{__version__}",
            }
        )

    def _get(self, path: str, **kwargs: Any) -> requests.Response:
        """GET is idempotent and may be retried with bounded backoff."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        retryable = {429, 500, 502, 503, 504}
        for attempt in range(self.max_get_retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                if attempt >= self.max_get_retries:
                    raise SpamhausError(f"Spamhaus GET failed: {exc}") from exc
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
        raise SpamhausError("Spamhaus GET failed")

    @staticmethod
    def _json(resp: requests.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text[:4000]}

    def threat_types(self) -> list[dict[str, Any]]:
        resp = self._get("lookup/threats-types")
        if resp.status_code != 200:
            raise SpamhausError(
                f"Threat type lookup failed HTTP {resp.status_code}: {resp.text[:1000]}"
            )
        data = self._json(resp)
        if not isinstance(data, list):
            raise SpamhausError(f"Unexpected threat type response: {data!r}")
        return [x for x in data if isinstance(x, dict)]

    def resolve_threat_type(self, preferred: str) -> str:
        preferred_lower = preferred.strip().lower()
        usable = [
            t for t in self.threat_types()
            if str(t.get("type", "")).lower() in {"*", "ip"}
        ]
        for t in usable:
            if str(t.get("code", "")).lower() == preferred_lower:
                return str(t["code"])
        for t in usable:
            if str(t.get("desc", "")).strip().lower() == preferred_lower:
                return str(t["code"])
        names = ", ".join(f"{t.get('code')} ({t.get('desc')})" for t in usable)
        raise SpamhausError(
            f"Configured threat type {preferred!r} is not available for IP submissions. "
            f"Available: {names}"
        )

    def iter_submissions(self, *, items: int = 1000, max_pages: int = 100):
        """Yield API-visible history page-by-page without retaining 30 days in RAM."""
        if not 1 <= items <= 10000:
            raise ValueError("items must be between 1 and 10000")
        if max_pages <= 0:
            raise ValueError("max_pages must be > 0")
        for page in range(1, max_pages + 1):
            resp = self._get("submissions/list", params={"items": items, "page": page})
            if resp.status_code != 200:
                raise SpamhausError(
                    f"Submission list failed HTTP {resp.status_code}: {resp.text[:1000]}"
                )
            data = self._json(resp)
            if not isinstance(data, list):
                raise SpamhausError(f"Unexpected submission list response: {data!r}")
            batch = [x for x in data if isinstance(x, dict)]
            for item in batch:
                yield item
            if len(batch) < items:
                return
        raise SpamhausError(
            f"Submission history exceeded the configured {max_pages} page safety bound; "
            "refusing to reconcile a potentially incomplete history."
        )

    def list_submissions(self, *, items: int = 1000, max_pages: int = 100) -> list[dict[str, Any]]:
        return list(self.iter_submissions(items=items, max_pages=max_pages))

    def submit_ip_once(self, ip: str, threat_type: str, reason: str) -> tuple[int, dict[str, Any]]:
        """Perform exactly one POST attempt, never an automatic retry.

        A transport timeout can happen after Spamhaus accepted the request. The
        caller must treat such failures as ambiguous and reconcile with the GET
        history endpoint instead of retrying immediately.
        """
        if len(reason) > 255 or len(reason.encode("utf-8")) > 255:
            raise ValueError("Spamhaus reason exceeds 255 characters/bytes")
        payload = {"threat_type": threat_type, "reason": reason, "source": {"object": ip}}
        url = f"{self.base_url}/submissions/add/ip"
        try:
            resp = self.session.post(
                url,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        except requests.RequestException as exc:
            raise SpamhausAmbiguousSubmissionError(
                f"Spamhaus POST outcome unknown for {ip}: {exc}"
            ) from exc
        body = self._json(resp)
        if not isinstance(body, dict):
            body = {"data": body}
        return resp.status_code, body
