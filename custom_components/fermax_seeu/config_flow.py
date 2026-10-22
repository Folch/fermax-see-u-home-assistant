"""Config flow for Fermax See-U integration."""

from __future__ import annotations

import json
import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import FermaxBlueApi
from .const import (
    CONF_DEVICE_IP,
    CONF_DEVICE_PIN,
    CONF_DEVICE_USERNAME,
    CONF_FERMAX_AUTH_BASIC,
    CONF_FERMAX_AUTH_URL,
    CONF_FERMAX_BASE_URL,
    CONF_FIREBASE_API_KEY,
    CONF_FIREBASE_APP_ID,
    CONF_FIREBASE_PACKAGE_NAME,
    CONF_FIREBASE_PROJECT_ID,
    CONF_FIREBASE_SENDER_ID,
    CONF_QR_ACCOUNT_ID,
    CONF_QR_CODE,
    CONF_QR_DEVICE_ID,
    CONF_QR_JSON,
    CONF_QR_MAC,
    CONF_QR_MODEL,
    CONF_QR_USER_ID,
    CONF_RECORDING_RETENTION,
    CONF_SCAN_INTERVAL,
    DEFAULT_RECORDING_RETENTION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)

CONF_AUTO_RESPONSE_FILE = "auto_response_file"

_LOGGER = logging.getLogger(__name__)

STEP_QR_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_QR_JSON): TextSelector(
            TextSelectorConfig(type=TextSelectorType.TEXT)
        ),
    }
)


def _https_url(value: str) -> str:
    """Validate that a URL uses HTTPS scheme."""
    url: str = vol.Url()(value)
    if not url.startswith("https://"):
        raise vol.Invalid("URL must use HTTPS")
    return url


STEP_CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Optional(
            CONF_FERMAX_AUTH_URL,
            default="https://oauth-pro-duoxme.fermax.io",
        ): str,
        vol.Optional(
            CONF_FERMAX_BASE_URL,
            default="https://pro-duoxme.fermax.io",
        ): str,
        vol.Optional(CONF_FERMAX_AUTH_BASIC, default=""): str,
        vol.Optional(CONF_FIREBASE_API_KEY, default=""): str,
        vol.Optional(CONF_FIREBASE_SENDER_ID, default="673285852721"): str,
        vol.Optional(CONF_FIREBASE_APP_ID, default=""): str,
        vol.Optional(CONF_FIREBASE_PROJECT_ID, default="fermax-see-u"): str,
        vol.Optional(CONF_FIREBASE_PACKAGE_NAME, default="com.fermax.see.u"): str,
    }
)


class FermaxSeeUConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fermax See-U."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._qr_data: dict[str, Any] = {}
        self._lan_data: dict[str, Any] = {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the QR step."""
        if user_input is not None:
            # Parse QR JSON
            try:
                qr_json_str = user_input[CONF_QR_JSON]
                qr_data = json.loads(qr_json_str)
            except json.JSONDecodeError:
                return self.async_show_form(
                    step_id="user",
                    data_schema=STEP_QR_SCHEMA,
                    errors={"base": "invalid_qr_json"},
                )

            # Validate required QR fields
            required_fields = ["u", "a", "d", "b"]  # user_id, account_id, device_id, mac
            if not all(field in qr_data for field in required_fields):
                return self.async_show_form(
                    step_id="user",
                    data_schema=STEP_QR_SCHEMA,
                    errors={"base": "invalid_qr_fields"},
                )

            self._qr_data = qr_data
            # Abort immediately if this device is already configured — the QR's
            # "u" is the device unique ID, and HA allows only one entry per
            # device. (Without this, the user walks the whole flow and only then
            # gets "already configured".)
            await self.async_set_unique_id(qr_data.get("u"))
            self._abort_if_unique_id_configured()
            return await self.async_step_lan()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_QR_SCHEMA,
        )

    async def async_step_lan(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the direct LAN connection step (See-U).

        The PIN is the per-device password set in the Fermax See-U app — every
        user enters their own device's PIN; there is no universal default.
        """
        if user_input is not None:
            ip = (user_input.get(CONF_DEVICE_IP) or "").strip()
            pin = (user_input.get(CONF_DEVICE_PIN) or "").strip()
            self._lan_data = {
                CONF_DEVICE_IP: ip,
                CONF_DEVICE_PIN: pin,
                CONF_DEVICE_USERNAME: (
                    user_input.get(CONF_DEVICE_USERNAME) or "adminapp2"
                ).strip(),
            }
            if not ip or not pin:
                return self.async_show_form(
                    step_id="lan",
                    data_schema=self._lan_schema(),
                    errors={"base": "required"},
                )
            errors = await self._validate_lan(self._lan_data)
            if errors:
                return self.async_show_form(
                    step_id="lan",
                    data_schema=self._lan_schema(),
                    errors=errors,
                )
            return await self.async_step_credentials()

        return self.async_show_form(
            step_id="lan",
            data_schema=self._lan_schema(),
        )

    def _lan_schema(self) -> vol.Schema:
        """Schema for the direct-LAN step (IP + PIN required)."""
        return vol.Schema(
            {
                vol.Required(CONF_DEVICE_IP): str,
                vol.Required(CONF_DEVICE_PIN): str,
                vol.Optional(CONF_DEVICE_USERNAME, default="adminapp2"): str,
            }
        )

    async def _validate_lan(self, lan_data: dict[str, Any]) -> dict[str, str]:
        """Best-effort validation: get.device.status with the given PIN.

        Returns an errors dict ({"base": "cannot_connect"}) on failure, or {}.
        """
        import hashlib
        import re

        import httpx

        pwd = hashlib.sha256(lan_data[CONF_DEVICE_PIN].encode("utf-8")).hexdigest()
        username = lan_data[CONF_DEVICE_USERNAME]
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<envelope>\n"
            "  <header>\n"
            "    <security>username</security>\n"
            f"    <username>{username}</username>\n"
            f"    <password>{pwd}</password>\n"
            "    <passwordencode>1</passwordencode>\n"
            "  </header>\n"
            "  <body>\n"
            "    <command>get.device.status</command>\n"
            "    <content/>\n"
            "  </body>\n"
            "</envelope>"
        )
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                resp = await client.post(
                    f"https://{lan_data[CONF_DEVICE_IP]}/tdkcgi",
                    headers={
                        "Content-Type": "application/xml",
                        "charset": "utf-8",
                    },
                    content=xml,
                )
            mac = re.search(r"<mac>([^<]+)</mac>", resp.text)
            err = re.search(r"<error>(\d+)</error>", resp.text)
            # Device answers 200 with error 0 + MAC only for a correct PIN.
            if resp.status_code != 200 or not mac or (err and err.group(1) != "0"):
                return {"base": "cannot_connect"}
            return {}
        except Exception:
            return {"base": "cannot_connect"}

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the API/Firebase credentials step."""
        if user_input is not None:
            data = {
                # QR data
                CONF_QR_JSON: json.dumps(self._qr_data),
                CONF_QR_USER_ID: self._qr_data.get("u"),
                CONF_QR_ACCOUNT_ID: self._qr_data.get("a"),
                CONF_QR_DEVICE_ID: self._qr_data.get("d"),
                CONF_QR_MAC: self._qr_data.get("b"),
                CONF_QR_MODEL: self._qr_data.get("m"),
                CONF_QR_CODE: self._qr_data.get("c"),
                # Direct LAN connection
                **self._lan_data,
                # Credentials
                **user_input,
            }
            return await self._async_validate_and_create(data)

        return self.async_show_form(
            step_id="credentials",
            data_schema=STEP_CREDENTIALS_SCHEMA,
        )

    async def _async_validate_and_create(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Validate credentials and create the config entry."""
        errors: dict[str, str] = {}
        for field in (CONF_FERMAX_AUTH_URL, CONF_FERMAX_BASE_URL):
            value = data.get(field, "")
            if value:
                try:
                    data[field] = _https_url(value)
                except vol.Invalid:
                    errors[field] = "invalid_url"
            else:
                data[field] = ""

        if errors:
            return self.async_show_form(
                step_id="credentials",
                data_schema=STEP_CREDENTIALS_SCHEMA,
                errors=errors,
            )

        # For Fermax See-U, use QR data directly (no OAuth validation needed)
        await self.async_set_unique_id(data[CONF_QR_USER_ID])
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=f"Fermax See-U ({data[CONF_QR_DEVICE_ID]})",
            data=data,
        )

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> FermaxSeeUOptionsFlow:
        """Return the options flow."""
        return FermaxSeeUOptionsFlow()


class FermaxSeeUOptionsFlow(OptionsFlow):
    """Handle options for Fermax See-U."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL),
                    ),
                    vol.Optional(
                        CONF_RECORDING_RETENTION,
                        default=self.config_entry.options.get(
                            CONF_RECORDING_RETENTION, DEFAULT_RECORDING_RETENTION
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=1, max=90),
                    ),
                    vol.Optional(
                        CONF_AUTO_RESPONSE_FILE,
                        default=self.config_entry.options.get(
                            CONF_AUTO_RESPONSE_FILE, "/config/media/mi_mensaje.wav"
                        ),
                    ): str,
                }
            ),
        )
