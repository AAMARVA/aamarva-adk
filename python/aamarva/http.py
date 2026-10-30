import os
import re
import time
import json
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, Dict, Any

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
    ("GET", re.compile(r"^/connections$")),
    ("GET", re.compile(r"^/connections/[^/]+/peer-key$")),
    ("GET", re.compile(r"^/connections/[^/]+/messages$")),
    ("POST", re.compile(r"^/connections/[^/]+/messages$")),
    ("GET", re.compile(r"^/clusters$")),
    ("GET", re.compile(r"^/clusters/[^/]+$")),
    ("GET", re.compile(r"^/clusters/[^/]+/messages$")),
    ("POST", re.compile(r"^/clusters/[^/]+/messages$")),
    ("GET", re.compile(r"^/clusters/[^/]+/key-distribution$")),
    ("GET", re.compile(r"^/floor/agent/tools$")),
    ("POST", re.compile(r"^/floor/tools/[^/]+/execute$")),
    ("POST", re.compile(r"^/floor/tools/[^/]+/request-access$")),
    ("GET", re.compile(r"^/floor/requests/[^/]+$")),
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

class HttpClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_ms: int = 15000,
        max_retries: int = 3,
    ):
        self.base_url = (base_url or os.getenv("AAMARVA_BASE_URL") or "https://aamarva.com/api").rstrip("/")
        self.agent_id = agent_id or os.getenv("AAMARVA_AGENT_ID")
        self.api_key = api_key or os.getenv("AAMARVA_API_KEY")
        self.timeout = timeout_ms / 1000.0
        self.max_retries = max_retries

        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.on_auth_success = None

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

    def _handle_error(self, code: int, body: str):
        if code == 401:
            raise AamarvaAuthenticationError("Authentication failed", status_code=401)
        elif code == 429:
            raise AamarvaRateLimitError("Rate limit exceeded", status_code=429)
        elif code >= 500:
            raise AamarvaAPIError(f"Server error: {body}", status_code=code)
        elif code >= 400:
            raise AamarvaAPIError(f"API error: {body}", status_code=code)

    def authenticate(self):
        if self.access_token:
            if self.on_auth_success:
                self.on_auth_success()
            return
        
        if not self.agent_id or not self.api_key:
            raise AamarvaAuthenticationError("Agent ID and API Key are required for authentication.")

        try:
            req = urllib.request.Request(
                f"{self.base_url}/auth/login",
                data=json.dumps({"agentId": self.agent_id, "apiKey": self.api_key}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                body = res.read().decode("utf-8")
                data = json.loads(body)
                
                if "data" in data:
                    data = data["data"]
                    
                if "tokens" in data and data["tokens"]:
                    self.access_token = data["tokens"].get("accessToken")
                    self.refresh_token = data["tokens"].get("refreshToken")
                else:
                    self.access_token = data.get("accessToken")
                    self.refresh_token = data.get("refreshToken")

                if self.on_auth_success and self.access_token:
                    self.on_auth_success()
                    
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            self._handle_error(e.code, body)
        except urllib.error.URLError as e:
            raise AamarvaConnectionError(f"Connection failed: {e.reason}")

    def request(
        self,
        method: str,
        path: str,
        auth: bool = True,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        skip_auto_auth: bool = False,
    ) -> Dict[str, Any]:
        norm_path = path if path.startswith("/") else "/" + path
        if not is_approved_endpoint(method, norm_path):
            raise AamarvaError(f"Endpoint not allowed by specification: {method} {norm_path}", code="ENDPOINT_NOT_ALLOWED")

        if auth and not skip_auto_auth:
            if not self.access_token:
                self.authenticate()
            elif self.on_auth_success:
                self.on_auth_success()

        headers = {}
        if auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        if json_data is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(json_data).encode("utf-8")
        else:
            data = None

        url = f"{self.base_url}{path}"
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            url = f"{url}?{query}"
            
        retries = 0
        is_idempotent = method.upper() in ("GET", "HEAD")

        while retries <= self.max_retries:
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    body = res.read().decode("utf-8")
                    return json.loads(body)
                    
            except urllib.error.HTTPError as e:
                if e.code == 401 and auth and retries == 0:
                    self.access_token = None
                    self.authenticate()
                    headers["Authorization"] = f"Bearer {self.access_token}"
                    retries += 1
                    continue

                if (e.code == 429 or e.code >= 500) and is_idempotent:
                    if retries < self.max_retries:
                        time.sleep((2 ** retries) * 0.5)
                        retries += 1
                        continue

                body = e.read().decode("utf-8")
                self._handle_error(e.code, body)
                
            except urllib.error.URLError as e:
                if is_idempotent:
                    if isinstance(e.reason, TimeoutError) or "timeout" in str(e.reason).lower():
                        if retries < self.max_retries:
                            retries += 1
                            continue
                        raise AamarvaTimeoutError("Request timed out")
                    
                    if retries < self.max_retries:
                        retries += 1
                        continue
                
                if isinstance(e.reason, TimeoutError) or "timeout" in str(e.reason).lower():
                    raise AamarvaTimeoutError("Request timed out")
                raise AamarvaConnectionError(f"Connection error: {e.reason}")
            
        raise AamarvaAPIError("Max retries exceeded")
