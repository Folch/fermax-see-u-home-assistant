"""The Fermax See-U integration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.httpx_client import create_async_httpx_client

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
    CONF_QR_DEVICE_ID,
    CONF_QR_MAC,
    CONF_QR_CODE,
    CONF_QR_USER_ID,
    CONF_RECORDING_RETENTION,
    CONF_SCAN_INTERVAL,
    DEFAULT_RECORDING_RETENTION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    FCM_WATCHDOG_INTERVAL,
    PLATFORMS,
    RECORDINGS_DIR,
)
from .coordinator import FermaxBlueCoordinator

_LOGGER = logging.getLogger(__name__)

type FermaxBlueConfigEntry = ConfigEntry[list[FermaxBlueCoordinator]]


_V2_REQUIRED_KEYS = {
    CONF_FERMAX_AUTH_URL,
    CONF_FERMAX_BASE_URL,
    CONF_FERMAX_AUTH_BASIC,
    CONF_FIREBASE_API_KEY,
    CONF_FIREBASE_SENDER_ID,
    CONF_FIREBASE_APP_ID,
    CONF_FIREBASE_PROJECT_ID,
    CONF_FIREBASE_PACKAGE_NAME,
}


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate a config entry to the current version.

    Version history:
      1 — Original format: only username + password (credentials were hardcoded).
      2 — API URL, auth basic, and Firebase credentials are now supplied by the user.
    """
    _LOGGER.debug("Migrating Fermax See-U config entry from version %s", config_entry.version)

    if config_entry.version < 2:
        # If the entry already has all v2 fields (added manually before the
        # VERSION bump existed), just promote it to v2.
        if _V2_REQUIRED_KEYS.issubset(config_entry.data.keys()):
            hass.config_entries.async_update_entry(config_entry, version=2)
            _LOGGER.info("Fermax See-U config entry migrated to version 2 (fields already present)")
            return True

        _LOGGER.error(
            "Fermax See-U config entry (version %s) cannot be automatically migrated to "
            "version 2. The integration now requires API and Firebase credentials that "
            "must be supplied manually (run extract_credentials.py to obtain them). "
            "Please delete this integration entry and re-add it.",
            config_entry.version,
        )
        return False

    return True


async def async_setup_entry(hass: HomeAssistant, entry: FermaxBlueConfigEntry) -> bool:
    """Set up Fermax See-U from a config entry."""
    client = create_async_httpx_client(hass)
    
    # Support both Blue (username/password) and See-U (QR parameters)
    api = FermaxBlueApi(
        entry.data.get("username", ""),
        entry.data.get("password", ""),
        client=client,
        auth_url=entry.data[CONF_FERMAX_AUTH_URL],
        base_url=entry.data[CONF_FERMAX_BASE_URL],
        auth_basic=entry.data[CONF_FERMAX_AUTH_BASIC],
        # See-U QR parameters
        qr_user_id=entry.data.get(CONF_QR_USER_ID),
        qr_account_id=entry.data.get(CONF_QR_ACCOUNT_ID),
        qr_device_id=entry.data.get(CONF_QR_DEVICE_ID),
        qr_mac=entry.data.get(CONF_QR_MAC),
        qr_auth_code=entry.data.get(CONF_QR_CODE),
        # See-U direct LAN connection
        device_ip=entry.data.get(CONF_DEVICE_IP),
        device_pin=entry.data.get(CONF_DEVICE_PIN),
        device_username=entry.data.get(CONF_DEVICE_USERNAME, "adminapp2"),
    )

    try:
        if api._device_ip:
            # Direct LAN connection: no cloud auth needed
            _LOGGER.info(
                "Fermax See-U direct connection: device_ip=%s (skipping cloud OAuth)",
                api._device_ip,
            )
            pairings = await api.get_pairings()
        else:
            await api.authenticate()
            pairings = await api.get_pairings()
    except Exception as err:
        await api.close()
        raise ConfigEntryNotReady(f"Failed to connect to Fermax API: {err}") from err

    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    auto_response_file = entry.options.get("auto_response_file", "")
    _sender_raw = entry.data.get(CONF_FIREBASE_SENDER_ID, "") or ""
    _sender_id = 0
    try:
        _sender_id = int(_sender_raw)
    except (TypeError, ValueError):
        _sender_id = 0
    firebase_config: dict[str, str | int] = {
        "firebase_api_key": entry.data.get(CONF_FIREBASE_API_KEY, ""),
        "firebase_sender_id": _sender_id,
        "firebase_app_id": entry.data.get(CONF_FIREBASE_APP_ID, ""),
        "firebase_project_id": entry.data.get(CONF_FIREBASE_PROJECT_ID, ""),
        "firebase_package_name": entry.data.get(CONF_FIREBASE_PACKAGE_NAME, ""),
    }

    coordinators: list[FermaxBlueCoordinator] = []

    for pairing in pairings:
        coordinator = FermaxBlueCoordinator(
            hass, api, pairing, scan_interval, auto_response_file, firebase_config
        )
        await coordinator.async_config_entry_first_refresh()

        # Notifications (FCM) only if Firebase credentials were provided.
        # A registration failure (e.g. the API key is restricted to the real
        # app) must NOT take down the whole integration — camera/stream/door
        # keep working, just without doorbell push events.
        if firebase_config.get("firebase_api_key"):
            try:
                storage_path = Path(hass.config.config_dir) / ".storage" / DOMAIN
                await asyncio.to_thread(storage_path.mkdir, parents=True, exist_ok=True)
                await coordinator.setup_notifications(storage_path)
            except Exception as err:
                _LOGGER.error(
                    "Failed to set up Fermax notifications (FCM). The "
                    "integration keeps working without doorbell push events: %s",
                    err,
                )

        coordinators.append(coordinator)

    entry.runtime_data = coordinators
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinators

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register send_audio service
    async def _handle_send_audio(call: ServiceCall) -> None:
        """Handle the send_audio service call."""
        audio_file = call.data.get("audio_file")
        message = call.data.get("message")
        language = call.data.get("language", "es")

        if not audio_file and not message:
            _LOGGER.error("send_audio: either audio_file or message is required")
            return

        # Validate audio_file path against HA media directories
        if audio_file:

            def _validate_path() -> bool:
                allowed_dirs = [
                    Path(str(d)).resolve()
                    for d in [
                        *hass.config.media_dirs.values(),
                        Path(hass.config.config_dir) / "media",
                    ]
                ]
                try:
                    resolved = Path(str(audio_file)).resolve()
                    return any(resolved == d or d in resolved.parents for d in allowed_dirs)
                except (OSError, ValueError):
                    return False

            if not await asyncio.to_thread(_validate_path):
                _LOGGER.error(
                    "send_audio: path %s is outside allowed media directories or invalid",
                    audio_file,
                )
                return

        # Find the coordinator with an active stream
        active_coordinator = None
        for coord in coordinators:
            if coord.stream_session and coord.stream_session.is_active:
                active_coordinator = coord
                break

        if not active_coordinator or not active_coordinator.stream_session:
            _LOGGER.error("send_audio: no active video stream")
            return

        # If message provided, generate TTS audio file
        if message and not audio_file:
            audio_file = await _generate_tts_audio(hass, message, language)
            if not audio_file:
                _LOGGER.error("send_audio: failed to generate TTS audio")
                return

        tts_generated = bool(message and not call.data.get("audio_file"))
        if audio_file:
            await active_coordinator.stream_session.send_audio(audio_file)
            # Clean up TTS temp file after use
            if tts_generated:
                with contextlib.suppress(OSError):
                    await asyncio.to_thread(Path(audio_file).unlink)

    if not hass.services.has_service(DOMAIN, "send_audio"):
        hass.services.async_register(
            DOMAIN,
            "send_audio",
            _handle_send_audio,
            schema=vol.Schema(
                {
                    vol.Optional("entity_id"): str,
                    vol.Optional("audio_file"): str,
                    vol.Optional("message"): str,
                    vol.Optional("language", default="es"): str,
                }
            ),
        )

    # Schedule recording cleanup
    async def _cleanup_old_recordings(_now: object = None) -> None:
        """Delete recordings older than retention period."""
        import time

        media_root = hass.config.media_dirs.get("local", "/media")
        recordings_path = Path(media_root) / RECORDINGS_DIR
        retention = entry.options.get(CONF_RECORDING_RETENTION, DEFAULT_RECORDING_RETENTION)
        cutoff = time.time() - (retention * 86400)

        def _do_cleanup() -> list[str]:
            """Perform blocking filesystem cleanup; return list of deleted filenames."""
            if not recordings_path.exists():
                return []
            deleted: list[str] = []
            for f in recordings_path.iterdir():
                if f.is_file() and f.stat().st_mtime < cutoff:
                    f.unlink()
                    deleted.append(f.name)
            return deleted

        deleted_files = await asyncio.to_thread(_do_cleanup)
        for name in deleted_files:
            _LOGGER.debug("Deleted old recording: %s", name)

    # Run cleanup once at startup (non-blocking) and daily
    hass.async_create_task(_cleanup_old_recordings())
    entry.async_on_unload(
        async_track_time_interval(hass, _cleanup_old_recordings, timedelta(hours=24))
    )

    async def _fcm_watchdog(_now: datetime | None = None) -> None:
        """Revive any FCM listener whose receiver has died."""
        await asyncio.gather(
            *(c.ensure_notifications_running() for c in coordinators),
            return_exceptions=True,
        )

    entry.async_on_unload(
        async_track_time_interval(hass, _fcm_watchdog, timedelta(seconds=FCM_WATCHDOG_INTERVAL))
    )

    async def _async_shutdown(event: Event) -> None:
        """Clean up on shutdown."""
        for coordinator in coordinators:
            await coordinator.stop_notifications()

    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_shutdown))
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))

    return True


async def _async_options_updated(hass: HomeAssistant, entry: FermaxBlueConfigEntry) -> None:
    """Handle options update — apply hot-reloadable options without full reload."""
    coordinators = hass.data[DOMAIN].get(entry.entry_id, [])

    new_scan = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    auto_response_file = entry.options.get("auto_response_file", "")

    needs_reload = False
    for coordinator in coordinators:
        coordinator._auto_response_file = auto_response_file
        # Scan interval change requires reload for update_interval to take effect
        old_scan = coordinator.update_interval
        if old_scan and old_scan != timedelta(minutes=new_scan):
            needs_reload = True

    if needs_reload:
        await hass.config_entries.async_reload(entry.entry_id)
    else:
        _LOGGER.info("Options updated (hot reload, no restart needed)")


async def _generate_tts_audio(hass: HomeAssistant, message: str, language: str) -> str | None:
    """Generate a WAV file from text using Google Translate TTS."""
    try:
        from gtts import gTTS

        def _generate_sync() -> str:
            tts = gTTS(text=message, lang=language)
            with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
                tts.save(f.name)
                return f.name

        path = await asyncio.to_thread(_generate_sync)
        _LOGGER.info("TTS audio generated: %s", path)
        return path
    except ImportError:
        _LOGGER.debug("gtts not available, trying HA tts service")
    except Exception:
        _LOGGER.exception("Failed to generate TTS audio")

    # Fallback: try using HA's built-in TTS
    try:
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as tts_file:
            tts_file.close()

        await hass.services.async_call(
            "tts",
            "google_translate_say",
            {
                "message": message,
                "language": language,
                "entity_id": "media_player.none",  # Dummy, we just want the file
            },
            blocking=True,
        )
        # HA TTS generates files in /config/tts/
        import glob

        def _find_latest_tts() -> str | None:
            files = sorted(
                glob.glob("/config/tts/*.mp3"),
                key=lambda f: Path(f).stat().st_mtime,
                reverse=True,
            )
            return files[0] if files else None

        result = await asyncio.to_thread(_find_latest_tts)
        if result:
            return result
    except Exception:
        _LOGGER.debug("HA TTS fallback failed", exc_info=True)

    return None


async def async_unload_entry(hass: HomeAssistant, entry: FermaxBlueConfigEntry) -> bool:
    """Unload a config entry."""
    coordinators = hass.data[DOMAIN].get(entry.entry_id, [])
    for coordinator in coordinators:
        await coordinator.stop_stream()
        await coordinator.stop_notifications()
        await coordinator.api.close()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
