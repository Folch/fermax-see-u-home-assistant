"""Fermax Blue API client."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from .const import APP_HEADERS

_LOGGER = logging.getLogger(__name__)


API_TIMEOUT = 10.0
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0
AUTH_RESPONSE_LOG_BODY_LIMIT = 500


def _redact_sensitive_text(text: str, extra_values: tuple[str | None, ...] = ()) -> str:
    """Redact known credential/token patterns from diagnostic text."""
    redacted = text
    for value in extra_values:
        if value:
            redacted = redacted.replace(value, "[redacted]")

    redacted = re.sub(
        r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+",
        r"\1 [redacted]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\bAuthorization\s*[:=]\s*(?:Basic|Bearer)?\s*[A-Za-z0-9._~+/=-]+",
        "[redacted]",
        redacted,
    )
    return re.sub(
        r'(?i)"?(?:access_token|refresh_token|id_token|password|username|email)"?\s*[:=]\s*"?[^",\s&}]+',
        "[redacted]",
        redacted,
    )


def _truncate_for_log(text: str, limit: int = AUTH_RESPONSE_LOG_BODY_LIMIT) -> str:
    """Return a bounded string suitable for logs."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


@dataclass(frozen=True)
class AccessDoor:
    """Represents a door that can be opened."""

    name: str
    title: str
    access_id: dict
    visible: bool


@dataclass(frozen=True)
class DeviceInfo:
    """Device information from Fermax."""

    device_id: str
    connection_state: str
    status: str
    family: str
    device_type: str
    subtype: str
    unit_number: int
    photocaller: bool
    streaming_mode: str
    is_monitor: bool
    wireless_signal: int


@dataclass(frozen=True)
class Pairing:
    """Represents a paired device."""

    device_id: str
    tag: str
    installation_id: str
    access_doors: dict[str, AccessDoor] = field(default_factory=dict)


@dataclass(frozen=True)
class CallLogEntry:
    """A call log entry with optional photo."""

    call_id: str
    device_id: str
    call_date: datetime
    photo_id: str | None = None
    answered: bool = False


@dataclass(frozen=True)
class DivertResponse:
    """Response from autoOn/changeVideoSource calls."""

    reason: str
    divert_service: str
    code: float
    description: str
    directed_to: str
    local_address: str = ""
    remote_address: str = ""


@dataclass(frozen=True)
class OpeningRecord:
    """A door opening history entry."""

    timestamp: str
    user: str
    door: str
    guest_email: str | None = None


def _parse_device_status_xml(xml_text: str) -> dict[str, Any]:
    """Parse a get.device.status response into a dict."""
    result: dict[str, Any] = {}
    mac = re.search(r"<mac>([^<]+)</mac>", xml_text)
    model = re.search(r"<model>([^<]+)</model>", xml_text)
    version = re.search(r"<version>([^<]+)</version>", xml_text)
    video = re.search(r"<vionoff>\s*<value>([^<]+)</value>", xml_text)
    timezone = re.search(r"<timezone>([^<]+)</timezone>", xml_text)
    error = re.search(r"<error>([^<]+)</error>", xml_text)
    if error:
        result["error"] = error.group(1)
    if mac:
        result["mac"] = mac.group(1)
    if model:
        result["model"] = model.group(1)
    if version:
        result["version"] = version.group(1)
    if video:
        result["video_on"] = video.group(1) == "video_on"
    if timezone:
        result["timezone"] = timezone.group(1)
    return result


def _is_retryable(exc: Exception) -> bool:
    """Return True if the exception is transient and worth retrying."""
    if isinstance(exc, httpx.ConnectError | httpx.TimeoutException):
        return True
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500


class FermaxAuthError(Exception):
    """Authentication error."""


class FermaxApiError(Exception):
    """Generic API error."""


class FermaxBlueApi:
    """Client for the Fermax Blue/See-U API."""

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        client: httpx.AsyncClient | None = None,
        *,
        auth_url: str,
        base_url: str,
        auth_basic: str,
        qr_user_id: str | None = None,
        qr_account_id: str | None = None,
        qr_device_id: str | None = None,
        qr_mac: str | None = None,
        qr_auth_code: str | None = None,
        device_ip: str | None = None,
        device_pin: str | None = None,
        device_username: str = "adminapp2",
        stream_key: str | None = None,
        client_id: str | None = None,
    ) -> None:
        """Initialize Fermax API client.

        For Fermax Blue: provide username and password.
        For Fermax See-U: provide QR parameters (qr_user_id, qr_account_id, etc.)
        plus the direct LAN connection details (device_ip, device_pin).
        """
        self._username = username or ""
        self._password = password or ""
        self._qr_user_id = qr_user_id
        self._qr_account_id = qr_account_id
        self._qr_device_id = qr_device_id
        self._qr_mac = qr_mac
        self._qr_auth_code = qr_auth_code
        self._device_ip = device_ip
        self._device_pin = device_pin or ""
        self._device_username = device_username or "adminapp2"
        self._stream_key = stream_key or ""
        # Default clientid of the videoporter (002-4112-{hex32}); the device
        # accepts this value in the QUII play packet.
        self._client_id = client_id or "002-4112-7F950C009611492F8C4D9D73FBC56215"
        self._access_token: str | None = None
        self._token_expires_at: float = 0
        self._auth_url = auth_url
        self._base_url = base_url
        self._auth_basic = auth_basic

        self._client = client
        self._owns_client = client is None
        self._device_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create a persistent HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=API_TIMEOUT)
            self._owns_client = True
        return self._client

    async def close(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client and self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        if self._device_client and not self._device_client.is_closed:
            await self._device_client.aclose()
            self._device_client = None

    # ------------------------------------------------------------------
    # Direct LAN (CGI) connection for Fermax See-U
    # ------------------------------------------------------------------

    def _device_cgi_url(self) -> str:
        """Return the device CGI URL."""
        if not self._device_ip:
            raise FermaxApiError("No device IP configured for direct connection")
        return f"https://{self._device_ip}/tdkcgi"

    def _device_pwd_hash(self) -> str:
        """SHA256 hash of the device PIN."""
        import hashlib

        return hashlib.sha256(self._device_pin.encode("utf-8")).hexdigest()

    def _build_device_xml(self, command: str, content: str = "") -> str:
        """Build a device CGI XML request."""
        pwd_hash = self._device_pwd_hash()
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<envelope>\n"
            "  <header>\n"
            "    <security>username</security>\n"
            f"    <username>{self._device_username}</username>\n"
            f"    <password>{pwd_hash}</password>\n"
            "    <passwordencode>1</passwordencode>\n"
            "  </header>\n"
            "  <body>\n"
            f"    <command>{command}</command>\n"
            f"    <content>{content}</content>\n"
            "  </body>\n"
            "</envelope>"
        )

    async def _device_cgi(self, command: str, content: str = "") -> httpx.Response:
        """Send a CGI command directly to the videoporter.

        Uses a dedicated client with TLS verification disabled because the
        device serves a self-signed certificate with a weak key.
        """
        xml = self._build_device_xml(command, content)
        headers = {
            "Content-Type": "application/xml",
            "charset": "utf-8",
            "Accept": "application/xml",
        }
        if self._device_client is None or self._device_client.is_closed:
            self._device_client = httpx.AsyncClient(
                timeout=API_TIMEOUT, verify=False
            )
        response = await self._device_client.post(
            self._device_cgi_url(), headers=headers, content=xml
        )
        response.raise_for_status()
        return response

    async def get_device_status_direct(self) -> dict[str, Any]:
        """Query get.device.status directly on the LAN device."""
        resp = await self._device_cgi("get.device.status")
        return _parse_device_status_xml(resp.text)

    async def open_door_direct(self) -> bool:
        """Open the door directly on the LAN device via CGI."""
        pwd_hash = self._device_pwd_hash()
        content = f"<door>1</door><locknumber>1</locknumber><password>{pwd_hash}</password>"
        try:
            resp = await self._device_cgi("set.device.opendoor", content)
            return "<error>0</error>" in resp.text
        except httpx.HTTPStatusError:
            return False

    async def get_stream_key_direct(self) -> str:
        """Fetch the QUII stream key (<key>) from the device and cache it.

        The <key> is the AES-256 key for the media stream on port 34567.
        Returns the key; also stores it in self._stream_key.
        """
        if self._stream_key:
            return self._stream_key
        try:
            resp = await self._device_cgi("get.device.streamkey")
            import re as _re

            key_match = _re.search(r"<key>(.*?)</key>", resp.text)
            if not key_match or not key_match.group(1):
                raise FermaxApiError("get.device.streamkey returned no <key>")
            self._stream_key = key_match.group(1)
            _LOGGER.debug("Fetched QUII stream key from %s", self._device_ip)
        except Exception as err:
            _LOGGER.warning("Failed to fetch stream key from device: %s", err)
            raise FermaxApiError("Could not fetch device stream key") from err
        return self._stream_key

    @property
    def is_authenticated(self) -> bool:
        """Return True if we have a valid token."""
        return self._access_token is not None and time.time() < self._token_expires_at

    def _safe_auth_response_body(self, response: httpx.Response) -> str:
        """Return a safe, bounded auth response body for diagnostics."""
        return _truncate_for_log(
            _redact_sensitive_text(
                response.text,
                (self._username, self._password, self._auth_basic),
            )
        )

    def _format_oauth_error(self, data: dict[str, Any]) -> str:
        """Build a safe, useful OAuth error message."""
        error = str(data.get("error", "unknown_error"))
        description = _redact_sensitive_text(
            str(data.get("error_description") or ""),
            (self._username, self._password, self._auth_basic),
        )

        if error == "invalid_client":
            return (
                "OAuth client authentication failed (invalid_client). Check the Fermax "
                "Auth Basic header/OAuth client credentials extracted from the APK."
            )

        if description and description != error:
            return f"OAuth authentication failed ({error}): {description}"
        return f"OAuth authentication failed: {error}"

    def _get_auth_headers(self) -> dict:
        """Get headers for authenticated API requests."""
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            **APP_HEADERS,
        }
        
        # Donem context al token genèric afegint les dades del QR a les capçaleres
        if self._qr_user_id:
            headers["userId"] = self._qr_user_id
            headers["X-User-Id"] = self._qr_user_id
        if self._qr_account_id:
            headers["accountId"] = self._qr_account_id
            headers["X-Account-Id"] = self._qr_account_id
            
        return headers

    async def authenticate(self) -> str:
        """Authenticate with Fermax Blue/See-U and return access token."""
        
        # 1. Assegurem el format de la capçalera (es necessita per password grant)
        auth_header = self._auth_basic
        if not auth_header.startswith("Basic "):
            auth_header = f"Basic {auth_header}"

        # Check if this is See-U (QR-based)
        if self._qr_user_id:
            _LOGGER.debug(
                "Fermax See-U: Autenticant amb grant_type=password. "
                "User ID: %s, Account ID: %s", self._qr_user_id, self._qr_account_id
            )

            # Password is the configured device PIN (from config, not hardcoded).
            qr_password = self._device_pin

            headers = {
                "Authorization": auth_header,
                "Content-Type": "application/x-www-form-urlencoded",
                "userId": self._qr_user_id,
                "X-User-Id": self._qr_user_id,
                **APP_HEADERS,
            }
            if self._qr_account_id:
                headers["accountId"] = self._qr_account_id
                headers["X-Account-Id"] = self._qr_account_id

            # Send the QR user (u) and the configured PIN.
            payload = f"grant_type=password&password={qr_password}&username={self._qr_user_id}"
            
            client = await self._get_client()
            
            auth_endpoint = f"{self._auth_url}/oauth/token"
            if self._auth_url.endswith("/oauth/token"): 
                auth_endpoint = self._auth_url
                
            response = await client.post(
                auth_endpoint,
                headers=headers,
                content=payload,
            )
            
            if response.status_code >= 400:
                _LOGGER.warning(
                    "Fermax See-U OAuth failed: status=%s body=%s",
                    response.status_code,
                    self._safe_auth_response_body(response),
                )
                raise FermaxAuthError(
                    f"Fermax See-U OAuth failed with HTTP {response.status_code}"
                )
            
            try:
                data = response.json()
            except ValueError as exc:
                raise FermaxApiError(
                    "Fermax See-U OAuth returned non-JSON response"
                ) from exc
            
            if "access_token" not in data:
                raise FermaxApiError(
                    "Fermax See-U OAuth response did not include access_token"
                )
            
            self._access_token = data["access_token"]
            self._token_expires_at = time.time() + data.get("expires_in", 3600) - 60
            _LOGGER.debug("Authenticated with Fermax See-U (Token OK!)")
            return self._access_token
            
        username = quote(self._username)
        password = quote(self._password)
        payload = f"grant_type=password&password={password}&username={username}"

        headers = {
            "Authorization": auth_header,
            "Content-Type": "application/x-www-form-urlencoded",
            **APP_HEADERS,
        }

        client = await self._get_client()
        response = await client.post(self._auth_url, headers=headers, content=payload)
        
        content_type = response.headers.get("content-type", "unknown")
        try:
            data = response.json()
        except ValueError as exc:
            _LOGGER.warning(
                "Fermax OAuth endpoint returned a non-JSON response: status=%s "
                "content_type=%s auth_url=%s body=%r",
                response.status_code,
                content_type,
                self._auth_url,
                self._safe_auth_response_body(response),
            )
            raise FermaxApiError(
                f"Fermax authentication returned a non-JSON response (HTTP {response.status_code})"
            ) from exc

        if not isinstance(data, dict):
            _LOGGER.warning(
                "Fermax OAuth endpoint returned unexpected JSON: status=%s "
                "content_type=%s auth_url=%s json_type=%s",
                response.status_code,
                content_type,
                self._auth_url,
                type(data).__name__,
            )
            raise FermaxApiError("Fermax authentication returned unexpected JSON")

        if "error" in data:
            message = self._format_oauth_error(data)
            _LOGGER.warning("Fermax OAuth authentication failed: %s", message)
            raise FermaxAuthError(message)

        if response.status_code >= 400:
            _LOGGER.warning(
                "Fermax OAuth endpoint returned HTTP %s without an OAuth error: "
                "content_type=%s auth_url=%s json_keys=%s",
                response.status_code,
                content_type,
                self._auth_url,
                sorted(data),
            )
            raise FermaxApiError(f"Fermax authentication failed with HTTP {response.status_code}")

        if "access_token" not in data:
            _LOGGER.warning(
                "Fermax OAuth response did not include access_token: status=%s "
                "content_type=%s auth_url=%s json_keys=%s",
                response.status_code,
                content_type,
                self._auth_url,
                sorted(data),
            )
            raise FermaxApiError("Fermax authentication response did not include access_token")

        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3600) - 60
        _LOGGER.debug("Authenticated with Fermax Blue")
        return self._access_token

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid token."""
        if not self.is_authenticated:
            await self.authenticate()

    async def get_access_token(self) -> str:
        """Return a fresh access token, re-authenticating if needed."""
        await self._ensure_authenticated()
        return self._access_token or ""

    async def _api_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated request with retry on transient errors."""
        await self._ensure_authenticated()
        client = await self._get_client()
        url = f"{self._base_url}{path}"
        headers = self._get_auth_headers()
        last_exc: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response: httpx.Response = await getattr(client, method)(
                    url, headers=headers, **kwargs
                )
                response.raise_for_status()
                return response
            except (
                httpx.HTTPStatusError,
                httpx.ConnectError,
                httpx.TimeoutException,
            ) as exc:
                last_exc = exc
                if not _is_retryable(exc) or attempt >= MAX_RETRIES:
                    raise
                delay = RETRY_BACKOFF_BASE * (2**attempt)
                _LOGGER.debug(
                    "Retryable error on %s %s (attempt %d/%d), retrying in %.1fs: %s",
                    method.upper(),
                    path,
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)

        # Should not reach here, but satisfy type checker
        raise last_exc  # type: ignore[misc]

    async def _api_get(self, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated GET request with retry."""
        return await self._api_request("get", path, **kwargs)

    async def _api_post(self, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated POST request with retry."""
        return await self._api_request("post", path, **kwargs)

    async def _api_put(self, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated PUT request with retry."""
        return await self._api_request("put", path, **kwargs)

    async def get_pairings(self) -> list[Pairing]:
        """Get all paired devices.

        For See-U with a direct LAN connection (device_ip configured),
        build the pairing from the QR data without contacting the cloud.
        """
        if self._device_ip:
            _LOGGER.debug(
                "See-U direct connection: building pairing from QR data (device_ip=%s)",
                self._device_ip,
            )
            default_door = AccessDoor(
                name="Door 1",
                title="Porta Principal",
                access_id={"id": 0},
                visible=True,
            )
            return [
                Pairing(
                    device_id=self._qr_device_id or self._device_ip,
                    tag="Fermax See-U",
                    installation_id=self._qr_account_id or "",
                    access_doors={"Door 1": default_door},
                )
            ]

        try:
            response = await self._api_get("/pairing/api/v4/pairings/me")
            data = response.json()
        except httpx.HTTPStatusError as exc:
            # Si l'API rebutja el /me (típic en See-U amb client_credentials)
            # i tenim el device_id del QR, fem un "fallback" manual per no bloquejar l'inici.
            if exc.response.status_code in (401, 403) and self._qr_device_id:
                _LOGGER.warning(
                    "El endpoint /me ha donat 401/403. "
                    "Generant Pairing manual a partir de les dades del QR per See-U."
                )
                
                # Creem una porta per defecte (Ajusta l'access_id si en provar d'obrir la porta et falla)
                default_door = AccessDoor(
                    name="Door 1",
                    title="Porta Principal",
                    access_id={"id": 0}, 
                    visible=True
                )
                
                return [
                    Pairing(
                        device_id=self._qr_device_id,
                        tag="Fermax See-U",
                        installation_id=self._qr_account_id or "",
                        access_doors={"Door 1": default_door}
                    )
                ]
            # Si l'error és un altre, tornem a llançar l'excepció
            raise

        pairings = []
        for item in data:
            access_doors = {}
            for door_name, door_data in item.get("accessDoorMap", {}).items():
                access_doors[door_name] = AccessDoor(
                    name=door_name,
                    title=door_data.get("title", door_name),
                    access_id=door_data["accessId"],
                    visible=door_data.get("visible", False),
                )

            pairings.append(
                Pairing(
                    device_id=item["deviceId"],
                    tag=item.get("tag", ""),
                    installation_id=item.get("installationId", ""),
                    access_doors=access_doors,
                )
            )

        return pairings

    async def get_device_info(self, device_id: str) -> DeviceInfo:
        """Get device information.

        For See-U direct connection, query the device over the LAN CGI.
        Otherwise fall back to the cloud API.
        """
        if self._device_ip:
            status = await self.get_device_status_direct()
            video_on = status.get("video_on", True)
            is_error = "error" in status and status.get("error") not in (None, "", "0")
            return DeviceInfo(
                device_id=self._qr_device_id or device_id,
                # "Connected" is what FermaxBlueEntity.available checks for.
                connection_state="Connected" if not is_error else "Disconnected",
                status="online" if not is_error else "offline",
                family="See-U",
                device_type=status.get("model", "Unknown"),
                subtype="",
                unit_number=1,
                photocaller=False,
                streaming_mode="direct" if video_on else "",
                is_monitor=False,
                wireless_signal=0,
            )

        response = await self._api_get(f"/deviceaction/api/v1/device/{device_id}")
        data = response.json()

        return DeviceInfo(
            device_id=data["deviceId"],
            connection_state=data.get("connectionState", "Unknown"),
            status=data.get("status", "Unknown"),
            family=data.get("family", "Unknown"),
            device_type=data.get("type", "Unknown"),
            subtype=data.get("subtype", ""),
            unit_number=data.get("unitNumber", 0),
            photocaller=data.get("photocaller", False),
            streaming_mode=data.get("streamingMode", ""),
            is_monitor=data.get("isMonitor", False),
            wireless_signal=data.get("wirelessSignal", 0),
        )

    async def open_door(self, device_id: str, access_id: dict) -> bool:
        """Open a door.

        For See-U direct connection, send the CGI opendoor command to the
        device over the LAN. Otherwise use the cloud API.
        """
        if self._device_ip:
            return await self.open_door_direct()
        try:
            await self._api_post(
                f"/deviceaction/api/v1/device/{device_id}/directed-opendoor",
                content=json.dumps(access_id),
            )
            return True
        except httpx.HTTPStatusError:
            return False

    async def open_door_incall(
        self,
        device_id: str,
        room_id: str | None = None,
        fcm_token: str | None = None,
        call_as: str | None = None,
    ) -> bool:
        """Open a door during an active call/stream session."""
        try:
            await self._api_post(
                "/deviceaction/api/v1/device/incall/opendoor",
                json={
                    "deviceId": device_id,
                    "roomId": room_id,
                    "appTokenId": fcm_token,
                    "unitId": call_as,
                },
            )
            return True
        except httpx.HTTPStatusError:
            return False

    async def get_call_log(self, fcm_token: str) -> list[CallLogEntry]:
        """Get call log entries."""
        try:
            response = await self._api_get(
                "/callmanager/api/v1/callregistry/participant",
                params={"appToken": fcm_token, "callRegistryType": "all"},
            )
        except httpx.HTTPStatusError:
            return []

        entries = []
        for item in response.json():
            entries.append(
                CallLogEntry(
                    call_id=item.get("id", ""),
                    device_id=item.get("deviceId", ""),
                    call_date=datetime.fromisoformat(
                        item.get("callDate", datetime.now(UTC).isoformat())
                    ),
                    photo_id=item.get("photoId"),
                    answered=item.get("answered", False),
                )
            )
        return entries

    async def get_call_photo(self, photo_id: str) -> bytes | None:
        """Get a photo from a call."""
        try:
            response = await self._api_get(
                "/callmanager/api/v1/photocall",
                params={"photoId": photo_id},
            )
        except httpx.HTTPStatusError:
            return None

        try:
            data = response.json()
            image_data = data.get("image", {}).get("data")
            if image_data:
                return base64.b64decode(image_data)
        except Exception:
            _LOGGER.debug("Failed to decode call photo", exc_info=True)
        return None

    async def auto_on(self, device_id: str, fcm_token: str) -> DivertResponse | None:
        """Start camera preview (auto-on) without a doorbell ring.

        This triggers the intercom to start streaming video to the app/client.
        The signaling server URL and room ID will arrive via push notification.
        """
        payload = {
            "directedToBluestream": fcm_token,
            "directedToSippo": None,
            "callAs": None,
        }

        try:
            response = await self._api_post(
                f"/deviceaction/api/v2/device/{device_id}/autoon",
                json=payload,
            )
        except httpx.HTTPStatusError as exc:
            _LOGGER.error("autoOn failed: %s", exc)
            return None

        data = response.json()
        additional = data.get("additional_info", {})
        local_info = additional.get("local", {})
        remote_info = additional.get("remote", {})

        return DivertResponse(
            reason=data.get("reason", ""),
            divert_service=data.get("divertService", ""),
            code=data.get("code", 0),
            description=data.get("description", ""),
            directed_to=data.get("directedTo", ""),
            local_address=local_info.get("address", ""),
            remote_address=remote_info.get("address", ""),
        )

    async def change_video_source(self, device_id: str, fcm_token: str) -> DivertResponse | None:
        """Request a video source change on the intercom."""
        payload = {
            "directedToBluestream": fcm_token,
            "directedToSippo": None,
            "callAs": None,
        }

        try:
            response = await self._api_post(
                f"/deviceaction/api/v2/device/{device_id}/changevideosource",
                json=payload,
            )
        except httpx.HTTPStatusError:
            return None

        data = response.json()
        return DivertResponse(
            reason=data.get("reason", ""),
            divert_service=data.get("divertService", ""),
            code=data.get("code", 0),
            description=data.get("description", ""),
            directed_to=data.get("directedTo", ""),
        )

    async def register_app_token(self, fcm_token: str, active: bool = True) -> bool:
        """Register FCM token with Fermax for push notifications."""
        payload = {
            "active": active,
            "token": fcm_token,
            "appVersion": "4.3.0",
            "locale": "en_US",
            "os": "Android",
            "osVersion": "14.0",
            "appBuild": "721",
            "phoneMobile": "HA-Integration",
        }

        try:
            await self._api_post("/notification/api/v1/apptoken", json=payload)
            return True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 409:
                _LOGGER.debug("Token conflict, updating existing token")
                try:
                    await self._api_post("/notification/api/v1/apptoken", json=payload)
                    return True
                except httpx.HTTPStatusError:
                    pass
            return False

    async def get_dnd_status(self, device_id: str, fcm_token: str) -> bool:
        """Get Do Not Disturb status for a device."""
        response = await self._api_get(
            "/notification/api/v1/mutedevice/me",
            params={"deviceId": device_id, "token": fcm_token},
        )
        data = response.json()
        # API returns bare bool or dict with "muted" key
        if isinstance(data, bool):
            return data
        return bool(data.get("muted", False)) if isinstance(data, dict) else bool(data)

    async def set_dnd(self, device_id: str, fcm_token: str, *, enabled: bool) -> None:
        """Set Do Not Disturb status for a device."""
        await self._api_post(
            "/notification/api/v1/mutedevice/me",
            json={"deviceId": device_id, "token": fcm_token, "muted": enabled},
        )

    async def press_f1(self, device_id: str) -> None:
        """Press the F1 button on the intercom."""
        await self._api_post(
            f"/deviceaction/api/v1/device/{device_id}/f1",
        )

    async def call_guard(self, device_id: str) -> None:
        """Call the guard/concierge."""
        await self._api_post(
            f"/deviceaction/api/v1/device/{device_id}/callguard",
        )

    async def ack_notification(self, message_id: str, *, is_call: bool) -> None:
        """Acknowledge a notification (call or info)."""
        path = "/callmanager/api/v1/message/ack" if is_call else "/notification/api/v1/message/ack"
        body = {"attended": True, "fcmMessageId": message_id}
        try:
            await self._api_post(path, json=body)
        except httpx.HTTPStatusError:
            _LOGGER.debug("Failed to ack notification %s", message_id)

    async def set_photo_caller(self, device_id: str, *, enabled: bool) -> None:
        """Enable or disable photo caller on a device."""
        await self._api_put(
            f"/deviceaction/api/v1/{device_id}/photocaller",
            params={"value": "true" if enabled else "false"},
        )

    async def get_opening_history(self, device_id: str) -> list[OpeningRecord]:
        """Get door opening history."""
        try:
            response = await self._api_get(
                "/rexistro/api/v1/opendoorregistry",
                params={"deviceId": device_id},
            )
        except Exception:
            _LOGGER.debug("Failed to get opening history", exc_info=True)
            return []

        data = response.json()
        entries = data.get("openDoorRegistry", [])
        return [
            OpeningRecord(
                timestamp=entry.get("instant", ""),
                user=entry.get("email", ""),
                door=entry.get("accessName", entry.get("accessType", "")),
                guest_email=entry.get("guestEmail"),
            )
            for entry in entries
        ]
