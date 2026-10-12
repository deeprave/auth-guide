"""Async HTTPS client for auth-guide's management API."""

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

DEFAULT_TIMEOUT = httpx.Timeout(5.0)
SETUP_TIMEOUT = httpx.Timeout(connect=5.0, read=None, write=5.0, pool=5.0)


class ManagementAPIError(RuntimeError):
    """A safe, displayable management API failure."""


@dataclass(frozen=True, slots=True)
class ManagementClientConfiguration:
    """Connection information for one management API request."""

    address: str
    bearer_token: str | None = None


class ManagementAPIClient:
    """Perform authenticated requests using the host's normal TLS trust store."""

    def __init__(self, configuration: ManagementClientConfiguration) -> None:
        if not configuration.address.startswith("https://"):
            raise ValueError("Management API address must use HTTPS")
        self._configuration = configuration

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> object:
        """Make one API request and return its decoded non-error response."""
        headers = {}
        if self._configuration.bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._configuration.bearer_token}"
        try:
            async with httpx.AsyncClient(
                base_url=self._configuration.address,
                headers=headers,
                timeout=timeout,
            ) as client:
                response = await client.request(method, path, json=json, params=params)
        except httpx.RequestError as error:
            raise ManagementAPIError(f"Could not reach the management API at {self._configuration.address}") from error
        if response.is_error:
            detail = "Request was rejected"
            try:
                response_body = response.json()
                detail = _safe_error_detail(response_body)
            except ValueError:
                pass
            raise ManagementAPIError(f"Management API request failed ({response.status_code}): {detail}")
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as error:
            raise ManagementAPIError("Management API returned an invalid response") from error


def _safe_error_detail(response_body: object) -> str:
    """Extract diagnostic messages without reflecting submitted request values."""
    if not isinstance(response_body, dict):
        return "Request was rejected"
    detail = response_body.get("detail")
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        messages = [item["msg"] for item in detail if isinstance(item, dict) and isinstance(item.get("msg"), str)]
        if messages:
            return "; ".join(messages)
    return "Request was rejected"
