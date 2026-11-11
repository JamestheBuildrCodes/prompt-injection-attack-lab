"""Target clients. The mock target is the default; external targets need explicit authorization."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from config.settings import MAX_RESPONSE_CHARS, REQUEST_TIMEOUT_S
from mock_target.target import DEFENSES, MockTarget

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.goog"}


class UnauthorizedTargetError(Exception):
    """Raised when an external target is configured without explicit authorization."""


@dataclass
class ClientResponse:
    text: str
    latency_ms: float
    error: str | None = None


class BaseClient:
    kind = "base"

    def describe(self) -> dict:  # safe to store and export: never contains secrets
        raise NotImplementedError

    def send(self, system_prompt: str, user_message: str, document: str | None = None) -> ClientResponse:
        raise NotImplementedError


class MockClient(BaseClient):
    kind = "mock"

    def __init__(self, defense: str = "basic"):
        if defense not in DEFENSES:
            raise ValueError(f"Unknown defense level '{defense}'.")
        self.defense = defense
        self._target = MockTarget(defense)

    def describe(self) -> dict:
        return {"type": "mock", "defense": self.defense, "authorized": True, "note": "Local simulated target. No network traffic."}

    def send(self, system_prompt: str, user_message: str, document: str | None = None) -> ClientResponse:
        t0 = time.perf_counter()
        try:
            text = self._target.respond(user_message, document, system_prompt)
            return ClientResponse(text, (time.perf_counter() - t0) * 1000)
        except Exception as exc:  # noqa: BLE001
            return ClientResponse("", (time.perf_counter() - t0) * 1000, f"mock target failed: {exc}")


@dataclass
class ExternalTargetConfig:
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    authorized: bool = False
    confirm_host: str = ""
    timeout_s: float = REQUEST_TIMEOUT_S

    @property
    def host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    def validate(self) -> None:
        """Refuse to proceed unless the operator explicitly authorized this exact host."""
        if not self.authorized:
            raise UnauthorizedTargetError(
                "Authorization required: confirm you own this system or have written permission to test it."
            )
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UnauthorizedTargetError("Base URL must look like https://host/v1.")
        if parsed.scheme == "http" and self.host not in LOCAL_HOSTS:
            raise UnauthorizedTargetError("Plain http is only allowed for localhost. Use https for remote targets.")
        if self.host in BLOCKED_HOSTS:
            raise UnauthorizedTargetError(f"Host '{self.host}' is blocked (cloud metadata endpoint).")
        if self.confirm_host.strip().lower() != self.host:
            raise UnauthorizedTargetError(f"Type the target hostname '{self.host}' to confirm it is the system you are authorized to test.")
        if not self.model.strip():
            raise UnauthorizedTargetError("Model name is required.")

    def public_dict(self) -> dict:
        return {"type": "external", "base_url": self.base_url, "host": self.host, "model": self.model,
                "authorized": self.authorized}


class OpenAICompatibleClient(BaseClient):
    kind = "external"

    def __init__(self, config: ExternalTargetConfig):
        config.validate()  # cannot construct without authorization
        self.config = config

    def describe(self) -> dict:
        return self.config.public_dict()

    def send(self, system_prompt: str, user_message: str, document: str | None = None) -> ClientResponse:
        content = user_message
        if document:
            content += f"\n\n<retrieved_document>\n{document}\n</retrieved_document>"
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        body = {"model": self.config.model, "temperature": 0,
                "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": content}]}
        t0 = time.perf_counter()
        try:
            r = requests.post(url, json=body, headers=headers, timeout=self.config.timeout_s)
            ms = (time.perf_counter() - t0) * 1000
            if r.status_code in (401, 403):
                return ClientResponse("", ms, f"Authentication failed (HTTP {r.status_code}). Check the API key.")
            if r.status_code == 429:
                return ClientResponse("", ms, "Rate limited (HTTP 429). Increase the request delay.")
            if r.status_code >= 400:
                return ClientResponse("", ms, f"HTTP {r.status_code} from target.")
            data = r.json()
            text = data["choices"][0]["message"]["content"] or ""
            return ClientResponse(text[:MAX_RESPONSE_CHARS], ms)
        except requests.Timeout:
            return ClientResponse("", (time.perf_counter() - t0) * 1000, "Request timed out.")
        except requests.RequestException as exc:
            return ClientResponse("", (time.perf_counter() - t0) * 1000, f"Network error: {type(exc).__name__}")
        except (KeyError, IndexError, ValueError):
            return ClientResponse("", (time.perf_counter() - t0) * 1000, "Unexpected response format from target.")
