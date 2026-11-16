import os
import re
import time
import json
import random
import threading
import urllib.request
import urllib.error
import urllib.parse
from email.utils import parsedate_to_datetime
from typing import Optional, Dict, Any, Callable

from .errors import (
    AamarvaError,
    AamarvaAPIError,
    AamarvaAuthenticationError,
    AamarvaRateLimitError,
    AamarvaTimeoutError,
    AamarvaConnectionError,
)

APPROVED_ENDPOINT_PATTERNS = [
    ("POST", re.compile(r"^/auth/login$")),
    ("POST", re.compile(r"^/auth/refresh$")),
    ("GET", re.compile(r"^/agents$")),
    ("GET", re.compile(r"^/agents/me$")),
    ("PATCH", re.compile(r"^/agents/me$")),
    ("GET", re.compile(r"^/agents/me/e2ee$")),
    ("PUT", re.compile(r"^/agents/me/e2ee$")),
    ("POST", re.compile(r"^/agents/me/e2ee$")),
    ("GET", re.compile(r"^/agents/[^/]+/e2ee$")),
    ("GET", re.compile(r"^/connections$")),
    ("GET", re.compile(r"^/connections/peer-key/[^/]+$")),
    ("GET", re.compile(r"^/connections/messages/[^/]+$")),
    ("POST", re.compile(r"^/connections/messages/[^/]+$")),
    ("GET", re.compile(r"^/clusters$")),
    ("GET", re.compile(r"^/clusters/[^/]+$")),
    ("GET", re.compile(r"^/clusters/[^/]+/messages$")),
    ("POST", re.compile(r"^/clusters/[^/]+/messages$")),
    ("GET", re.compile(r"^/clusters/[^/]+/key-distribution$")),
    ("POST", re.compile(r"^/clusters/[^/]+/key-distribution$")),
    ("GET", re.compile(r"^/floor/agent/tools$")),
    ("GET", re.compile(r"^/floor/tools/[^/]+/policy$")),
    ("POST", re.compile(r"^/floor/tools/[^/]+/invoke$")),
    ("GET", re.compile(r"^/floor/requests/[^/]+$")),
    ("POST", re.compile(r"^/floor/invocations/[^/]+/execute$")),
    ("POST", re.compile(r"^/floor/invocations/[^/]+/access$")),
    ("GET", re.compile(r"^/adk$")),
    ("GET", re.compile(r"^/watchtower/activity$")),
    ("POST", re.compile(r"^/watchtower/stream-ticket$")),
    ("GET", re.compile(r"^/watchtower/stream$")),
    ("GET", re.compile(r"^/agent/footprints$")),
    ("GET", re.compile(r"^/webhooks/events$")),
]


def is_approved_endpoint(method: str, path: str) -> bool:
    norm_method = method.upper()
    norm_path = path if path.startswith("/") else "/" + path
    clean_path = norm_path.split("?")[0]
    for m, pattern in APPROVED_ENDPOINT_PATTERNS:
        if m == norm_method and pattern.match(clean_path):
            return True
    return False


def _parse_retry_after(header_val: Optional[str]) -> Optional[float]:
    if not header_val:
        return None
    trimmed = header_val.strip()
    if trimmed.isdigit():
        return max(0.0, float(int(trimmed)))
    try:
        dt = parsedate_to_datetime(trimmed)
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


class HttpClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_ms: int = 15000,
        max_retries: int = 3,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        auto_login: bool = True,
    ):
        self.base_url = (base_url or os.getenv("AAMARVA_BASE_URL") or "https://aamarva.com/api").rstrip("/")
        self.agent_id = agent_id or os.getenv("AAMARVA_AGENT_ID")
        self.api_key = api_key or os.getenv("AAMARVA_API_KEY")
        self.timeout = timeout_ms / 1000.0
        self.max_retries = max_retries

        self.access_token: Optional[str] = access_token or os.getenv("AAMARVA_ACCESS_TOKEN")
        self.refresh_token: Optional[str] = refresh_token or os.getenv("AAMARVA_REFRESH_TOKEN")
        raw_target = target_agent_id if target_agent_id is not None else os.getenv("AAMARVA_TARGET_AGENT_ID")
        self.target_agent_id: Optional[str] = raw_target.strip() if isinstance(raw_target, str) and raw_target.strip() else None
        self.auto_login = auto_login

        self.on_auth_success: Optional[Callable[[], None]] = None
        self.on_target_agent_id_change: Optional[Callable[[Optional[str]], None]] = None

        self._auth_lock = threading.Lock()
        self._refresh_lock = threading.Lock()

    def set_credentials(
        self,
        agent_id: str,
        api_key: str,
        preserve_tokens: bool = False,
        tokens: Optional[Dict[str, str]] = None
    ) -> None:
        self.agent_id = agent_id
        self.api_key = api_key
        if tokens:
            self.access_token = tokens.get("accessToken")
            self.refresh_token = tokens.get("refreshToken")
        elif not preserve_tokens:
            self.access_token = None
            self.refresh_token = None

    def set_tokens(self, tokens: Dict[str, str]) -> None:
        self.access_token = tokens.get("accessToken")
        self.refresh_token = tokens.get("refreshToken")

    def get_tokens(self) -> Dict[str, Optional[str]]:
        return {
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
        }

    def set_target_agent_id(self, target_agent_id: Optional[str] = None) -> None:
        normalized = target_agent_id.strip() if isinstance(target_agent_id, str) and target_agent_id.strip() else None
        if self.target_agent_id != normalized:
            self.target_agent_id = normalized
            if self.on_target_agent_id_change:
                self.on_target_agent_id_change(self.target_agent_id)

    def get_target_agent_id(self) -> Optional[str]:
        return self.target_agent_id

    def _extract_error_message(self, body: str) -> str:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                err = parsed.get("error")
                if isinstance(err, dict) and err.get("message"):
                    return str(err["message"])
                if isinstance(err, str) and err:
                    return err
                if parsed.get("message"):
                    return str(parsed["message"])
        except Exception:
            pass
        return body

    def _handle_error(self, code: int, body: str):
        msg = self._extract_error_message(body)
        if code == 401:
            raise AamarvaAuthenticationError(msg or "Authentication failed", status_code=401)
        elif code == 429:
            raise AamarvaRateLimitError(msg or "Rate limit exceeded", status_code=429)
        elif code >= 500:
            raise AamarvaAPIError(f"Server error: {msg}", status_code=code)
        elif code >= 400:
            raise AamarvaAPIError(f"API error: {msg}", status_code=code)

    def _build_headers(
        self,
        auth: bool = True,
        has_body: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        if has_body:
            headers.setdefault("Content-Type", "application/json")
        if auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if self.target_agent_id and "x-target-agent-id" not in headers:
            headers["x-target-agent-id"] = self.target_agent_id
        return headers

    def authenticate(self) -> None:
        with self._auth_lock:
            if self.access_token:
                if self.on_auth_success:
                    self.on_auth_success()
                return

            if not self.agent_id or not self.api_key:
                raise AamarvaAuthenticationError("Agent ID and API Key are required for authentication.")

            headers = self._build_headers(auth=False, has_body=True)
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/auth/login",
                    data=json.dumps({"agentId": self.agent_id, "apiKey": self.api_key}).encode("utf-8"),
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    body = res.read().decode("utf-8")
                    raw = json.loads(body)
                    data = raw.get("data", raw) if isinstance(raw, dict) else {}

                    if isinstance(data, dict) and isinstance(data.get("tokens"), dict):
                        self.access_token = data["tokens"].get("accessToken")
                        self.refresh_token = data["tokens"].get("refreshToken")
                    elif isinstance(data, dict):
                        self.access_token = data.get("accessToken")
                        self.refresh_token = data.get("refreshToken")

                    if self.on_auth_success and self.access_token:
                        self.on_auth_success()

            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8")
                self._handle_error(e.code, body)
            except urllib.error.URLError as e:
                raise AamarvaConnectionError(f"Connection failed: {e.reason}")

    def refresh_access_token(self) -> bool:
        if not self.refresh_token:
            return False

        with self._refresh_lock:
            if not self.refresh_token:
                return False

            headers = self._build_headers(auth=False, has_body=True)
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/auth/refresh",
                    data=json.dumps({"refreshToken": self.refresh_token}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    body = res.read().decode("utf-8")
                    raw = json.loads(body)
                    data = raw.get("data", raw) if isinstance(raw, dict) else {}
                    tokens = data.get("tokens") if isinstance(data, dict) and isinstance(data.get("tokens"), dict) else data
                    next_access = tokens.get("accessToken") if isinstance(tokens, dict) else None
                    next_refresh = tokens.get("refreshToken") if isinstance(tokens, dict) else None
                    if next_access and isinstance(next_access, str):
                        self.access_token = next_access
                        if next_refresh and isinstance(next_refresh, str):
                            self.refresh_token = next_refresh
                        if self.on_auth_success:
                            self.on_auth_success()
                        return True
                    self.access_token = None
                    return False
            except Exception:
                self.access_token = None
                return False

    def _raw_request(
        self,
        method: str,
        path: str,
        auth: bool = True,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        norm_method = method.upper()
        norm_path = path if path.startswith("/") else "/" + path
        if not is_approved_endpoint(norm_method, norm_path):
            raise AamarvaError(f"Endpoint not allowed by specification: {norm_method} {norm_path}", code="ENDPOINT_NOT_ALLOWED")

        data_bytes = None
        has_body = json_data is not None and norm_method not in ("GET", "HEAD")
        if has_body:
            data_bytes = json.dumps(json_data).encode("utf-8")

        url = f"{self.base_url}{norm_path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                query = urllib.parse.urlencode(filtered)
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{query}"

        is_idempotent = norm_method in ("GET", "HEAD")
        max_attempts = self.max_retries if is_idempotent else 0
        attempt = 0

        while attempt <= max_attempts:
            headers = self._build_headers(auth=auth, has_body=has_body)
            try:
                req = urllib.request.Request(url, data=data_bytes, headers=headers, method=norm_method)
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    body = res.read().decode("utf-8")
                    if not body.strip():
                        return {"success": True, "data": None}
                    return json.loads(body)

            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8")
                retry_after = _parse_retry_after(e.headers.get("Retry-After") if e.headers else None)
                if (e.code == 429 or 500 <= e.code <= 504) and is_idempotent and attempt < max_attempts:
                    delay = min((2 ** (attempt + 1)) * 0.3, 5.0) + random.uniform(0.0, 0.15)
                    if e.code == 429 and retry_after is not None:
                        delay = max(delay, retry_after)
                    time.sleep(delay)
                    attempt += 1
                    continue
                self._handle_error(e.code, body)

            except urllib.error.URLError as e:
                is_timeout = isinstance(e.reason, TimeoutError) or "timeout" in str(e.reason).lower()
                if is_idempotent and attempt < max_attempts:
                    delay = min((2 ** (attempt + 1)) * 0.3, 5.0) + random.uniform(0.0, 0.15)
                    time.sleep(delay)
                    attempt += 1
                    continue
                if is_timeout:
                    raise AamarvaTimeoutError("Request timed out")
                raise AamarvaConnectionError(f"Connection error: {e.reason}")

        raise AamarvaAPIError("Max retries exceeded")

    def request(
        self,
        method: str,
        path: str,
        auth: bool = True,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        skip_auto_auth: bool = False,
    ) -> Dict[str, Any]:
        norm_method = method.upper()
        norm_path = path if path.startswith("/") else "/" + path
        if not is_approved_endpoint(norm_method, norm_path):
            raise AamarvaError(f"Endpoint not allowed by specification: {norm_method} {norm_path}", code="ENDPOINT_NOT_ALLOWED")

        if auth and self.auto_login and not skip_auto_auth:
            if not self.access_token:
                self.authenticate()
            elif self.on_auth_success:
                self.on_auth_success()

        try:
            return self._raw_request(norm_method, norm_path, auth=auth, params=params, json_data=json_data)
        except AamarvaAuthenticationError:
            if auth:
                if self.refresh_access_token():
                    return self._raw_request(norm_method, norm_path, auth=auth, params=params, json_data=json_data)
                if self.agent_id and self.api_key:
                    self.access_token = None
                    self.refresh_token = None
                    self.authenticate()
                    return self._raw_request(norm_method, norm_path, auth=auth, params=params, json_data=json_data)
                self.access_token = None
            raise

    def open_stream(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        auth: bool = True,
        timeout: Optional[float] = None,
    ):
        norm_path = path if path.startswith("/") else "/" + path
        if not is_approved_endpoint("GET", norm_path):
            raise AamarvaError(f"Endpoint not allowed by specification: GET {norm_path}", code="ENDPOINT_NOT_ALLOWED")

        if auth and self.auto_login and not self.access_token and self.agent_id and self.api_key:
            self.authenticate()

        url = f"{self.base_url}{norm_path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = f"{url}?{urllib.parse.urlencode(filtered)}"

        headers = self._build_headers(
            auth=auth,
            has_body=False,
            extra_headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
        )
        req = urllib.request.Request(url, headers=headers, method="GET")
        return urllib.request.urlopen(req, timeout=timeout if timeout is not None else 60.0)
