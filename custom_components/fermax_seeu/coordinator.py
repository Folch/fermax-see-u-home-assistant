"""Data coordinator for Fermax Blue integration."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    CallLogEntry,
    DeviceInfo,
    DivertResponse,
    FermaxApiError,
    FermaxAuthError,
    FermaxBlueApi,
    OpeningRecord,
    Pairing,
)
from .const import (
    CALL_MODE_AUTO_RESPOND,
    CALL_MODE_NOTIFY,
    DEFAULT_STREAM_DURATION,
    DOMAIN,
    MIN_STREAM_DURATION,
    RECORDINGS_DIR,
    SIGNAL_CALL_ENDED,
    SIGNAL_CAMERA_ON,
    SIGNAL_DIRECT_STREAM_CHANGED,
    SIGNAL_DOOR_OPENED,
    SIGNAL_DOORBELL_RING,
)
from .notification import FermaxNotificationListener, _redact_notification
from .streaming import DEFAULT_SIGNALING_URL, FermaxStreamSession, streaming_deps_available

_LOGGER = logging.getLogger(__name__)

DOORBELL_RESET_SECONDS = 30
CAMERA_TIMEOUT_SECONDS = 90
# Direct-LAN stream is ON DEMAND: the videoporter only accepts ONE viewer at a
# time, so HA must not hold the stream when nobody is watching (or the phone
# app loses access). These bound how long it stays up after a button press /
# after the last camera viewer leaves.
DIRECT_STREAM_TIMEOUT = 120
DIRECT_STREAM_VIEWER_GRACE = 8
# FCM re-delivers recent notifications when the listener reconnects after a
# reload/restart, causing phantom doorbell rings. Ignore them briefly.
NOTIFICATION_GRACE_PERIOD = 10
ALLOWED_SIGNALING_DOMAIN = ".fermax.io"


def _is_trusted_signaling_url(url: str) -> bool:
    """Reject signaling URLs outside known Fermax domains."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host.endswith(ALLOWED_SIGNALING_DOMAIN) or host == "fermax.io"
    except ValueError:
        return False


class FermaxBlueCoordinator(DataUpdateCoordinator):
    """Coordinate data updates and notifications for a Fermax Blue device."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: FermaxBlueApi,
        pairing: Pairing,
        scan_interval: int = 5,
        auto_response_file: str = "",
        firebase_config: dict[str, str | int] | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{pairing.device_id}",
            update_interval=timedelta(minutes=scan_interval),
        )
        self.api = api
        self.pairing = pairing
        self.device_info: DeviceInfo | None = None
        self.notification_listener: FermaxNotificationListener | None = None
        self._last_photo: bytes | None = None
        self._last_photo_id: str | None = None
        self._doorbell_ringing: bool = False
        self._camera_active: bool = False

        self._photo_fetch_pending: bool = False
        self._doorbell_reset_unsub: CALLBACK_TYPE | None = None
        self._camera_timeout_unsub: CALLBACK_TYPE | None = None
        self._dnd_enabled: bool | None = None
        self._last_opening: OpeningRecord | None = None
        self._last_call: CallLogEntry | None = None
        self._call_log: list[CallLogEntry] = []
        self._stream_session: FermaxStreamSession | None = None
        self._direct_stream = None  # SeeuDirectStream (direct LAN, See-U)
        self._direct_viewers = 0
        self._direct_manual = False  # set when the user toggled the stream switch
        self._direct_stop_unsub: CALLBACK_TYPE | None = None
        self._storage_path: Path | None = None
        self._auto_response_file = auto_response_file
        self._call_mode = CALL_MODE_NOTIFY
        self._stream_duration = DEFAULT_STREAM_DURATION
        self._stream_stop_unsub: CALLBACK_TYPE | None = None
        self._firebase_config = firebase_config or {}
        self._processed_notifications: deque[str] = deque(maxlen=100)
        self._notification_start_time: float | None = None

    @property
    def call_mode(self) -> str:
        """Return the current call mode."""
        return self._call_mode

    @call_mode.setter
    def call_mode(self, value: str) -> None:
        """Set the call mode."""
        self._call_mode = value

    @property
    def stream_duration(self) -> int:
        """Return the configured stream duration in seconds."""
        return self._stream_duration

    @stream_duration.setter
    def stream_duration(self, value: int) -> None:
        """Set the stream duration in seconds."""
        self._stream_duration = value

    @property
    def last_photo(self) -> bytes | None:
        """Return the last captured photo."""
        return self._last_photo

    def _last_frame_path(self) -> Path | None:
        """Return the path for persisting the last camera frame."""
        if self._storage_path:
            return self._storage_path / f"last_frame_{self.pairing.device_id}.jpg"
        return None

    async def _save_last_photo(self) -> None:
        """Persist last photo to disk for survival across restarts."""
        path = self._last_frame_path()
        if path and self._last_photo:
            await asyncio.to_thread(path.write_bytes, self._last_photo)

    async def _save_call_photo(self, photo: bytes) -> None:
        """Save a doorbell call photo to the recordings directory."""
        from datetime import datetime

        media_root = self.hass.config.media_dirs.get("local", "/media")
        recordings_dir = Path(media_root) / RECORDINGS_DIR
        await asyncio.to_thread(recordings_dir.mkdir, parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = recordings_dir / f"{timestamp}_photo.jpg"
        await asyncio.to_thread(path.write_bytes, photo)
        _LOGGER.info("Call photo saved: %s (%d KB)", path, len(photo) // 1024)

    async def _load_last_photo(self) -> None:
        """Load persisted last photo from disk."""
        path = self._last_frame_path()
        if path:

            def _read() -> bytes | None:
                if path.exists():
                    return path.read_bytes()
                return None

            photo = await asyncio.to_thread(_read)
            if photo:
                self._last_photo = photo
                _LOGGER.info("Loaded persisted camera frame (%d bytes)", len(photo))

    @property
    def doorbell_ringing(self) -> bool:
        """Return True if the doorbell is currently ringing."""
        return self._doorbell_ringing

    @property
    def camera_active(self) -> bool:
        """Return True if camera preview is active."""
        return self._camera_active

    @property
    def dnd_enabled(self) -> bool | None:
        """Return DND state."""
        return self._dnd_enabled

    @property
    def last_opening(self) -> OpeningRecord | None:
        """Return the last door opening record."""
        return self._last_opening

    @property
    def last_call(self) -> CallLogEntry | None:
        """Return the most recent call log entry."""
        return self._last_call

    @property
    def call_log(self) -> list[CallLogEntry]:
        """Return recent call log entries."""
        return self._call_log

    @property
    def stream_session(self) -> FermaxStreamSession | None:
        """Return the active stream session, if any."""
        return self._stream_session

    @property
    def direct_stream(self):
        """Return the persistent direct-LAN stream session (See-U), if any."""
        return self._direct_stream

    def _notify_direct_stream_changed(self) -> None:
        """Dispatch the stream-changed signal safely from any thread.

        async_dispatcher_send must only run on the event loop. The direct
        stream may change from a worker thread (its own session thread), so we
        hop to the loop with call_soon_threadsafe.
        """
        signal = SIGNAL_DIRECT_STREAM_CHANGED.format(self.pairing.device_id)
        self.hass.loop.call_soon_threadsafe(async_dispatcher_send, self.hass, signal)

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from the API.

        Only fetches device info on each poll (1 API call per 5 min).
        Call log and photos are only fetched after a doorbell ring event
        to minimize unnecessary API requests.
        """
        try:
            device_info = await self.api.get_device_info(self.pairing.device_id)
        except (FermaxAuthError, FermaxApiError) as err:
            raise UpdateFailed(f"Error fetching device info: {err}") from err
        except Exception as err:
            raise UpdateFailed(f"Unexpected error: {err}") from err

        self.device_info = device_info

        # In direct-LAN mode (See-U) the cloud API is not available and these
        # fetches would only trigger failed OAuth attempts — skip them.
        direct_mode = bool(getattr(self.api, "_device_ip", None))

        if not direct_mode:
            # Fetch call log if FCM token is available
            if self.notification_listener and self.notification_listener.fcm_token:
                try:
                    call_log = await self.api.get_call_log(self.notification_listener.fcm_token)
                    self._call_log = call_log
                    if call_log:
                        self._last_call = max(call_log, key=lambda c: c.call_date)

                        # Fetch photo only after a doorbell ring
                        if self._photo_fetch_pending:
                            self._photo_fetch_pending = False
                            latest = self._last_call
                            if latest.photo_id and latest.photo_id != self._last_photo_id:
                                photo = await self.api.get_call_photo(latest.photo_id)
                                if photo:
                                    self._last_photo = photo
                                    self._last_photo_id = latest.photo_id
                                    self.hass.async_create_task(self._save_call_photo(photo))
                except Exception:
                    _LOGGER.debug("Failed to fetch call log/photo", exc_info=True)

            # Fetch DND status
            if self.notification_listener and self.notification_listener.fcm_token:
                try:
                    self._dnd_enabled = await self.api.get_dnd_status(
                        self.pairing.device_id,
                        self.notification_listener.fcm_token,
                    )
                except Exception:
                    _LOGGER.debug("Failed to fetch DND status", exc_info=True)

            # Fetch latest door opening (1 API call, lightweight)
            try:
                openings = await self.api.get_opening_history(self.pairing.device_id)
                if openings:
                    self._last_opening = openings[0]
            except Exception:
                _LOGGER.debug("Failed to fetch opening history", exc_info=True)

        return {
            "device_id": device_info.device_id,
            "connection_state": device_info.connection_state,
            "status": device_info.status,
            "family": device_info.family,
            "type": device_info.device_type,
            "subtype": device_info.subtype,
            "unit_number": device_info.unit_number,
            "photocaller": device_info.photocaller,
            "streaming_mode": device_info.streaming_mode,
            "is_monitor": device_info.is_monitor,
            "wireless_signal": device_info.wireless_signal,
        }

    async def setup_notifications(self, storage_path: Path) -> None:
        """Set up the FCM notification listener."""
        self._storage_path = storage_path
        self.notification_listener = FermaxNotificationListener(
            hass=self.hass,
            notification_callback=self._handle_notification,
            firebase_api_key=str(self._firebase_config.get("firebase_api_key", "")),
            firebase_sender_id=self._firebase_config.get("firebase_sender_id", 0),
            firebase_app_id=str(self._firebase_config.get("firebase_app_id", "")),
            firebase_project_id=str(self._firebase_config.get("firebase_project_id", "")),
            firebase_package_name=str(self._firebase_config.get("firebase_package_name", "")),
        )

        # Load persisted last photo for camera preview
        await self._load_last_photo()

        try:
            fcm_token = await self.notification_listener.register()
        except Exception as err:
            _LOGGER.error(
                "FCM registration failed — doorbell push notifications are "
                "disabled, but the rest of the integration keeps working: %s",
                err,
            )
            self.notification_listener = None
            return

        if fcm_token:
            await self.api.register_app_token(fcm_token, active=True)
            self._notification_start_time = time.monotonic()
            await self.notification_listener.start()
            _LOGGER.info(
                "Notification listener started for device %s",
                self.pairing.device_id,
            )

    async def stop_notifications(self) -> None:
        """Stop the notification listener."""
        if self.notification_listener:
            if self.notification_listener.fcm_token:
                await self.api.register_app_token(
                    self.notification_listener.fcm_token, active=False
                )
            await self.notification_listener.stop()

    async def ensure_notifications_running(self) -> None:
        """Watchdog hook: revive the FCM listener if it died."""
        if self.notification_listener:
            await self.notification_listener.ensure_running()

    @callback
    def _handle_notification(self, notification: dict, persistent_id: str) -> None:
        """Handle an incoming FCM doorbell notification."""
        # After a reload/restart, FCM re-delivers recent notifications.
        # Ignore them during the grace period to avoid phantom doorbell rings.
        if (
            self._notification_start_time is not None
            and time.monotonic() - self._notification_start_time < NOTIFICATION_GRACE_PERIOD
        ):
            _LOGGER.debug(
                "Ignoring re-delivered notification during grace period: %s",
                persistent_id,
            )
            return

        # Skip already-processed notifications (re-delivered on FCM reconnect)
        if persistent_id in self._processed_notifications:
            _LOGGER.debug("Skipping duplicate notification: %s", persistent_id)
            return
        self._processed_notifications.append(persistent_id)

        _LOGGER.info(
            "Doorbell notification for %s: %s",
            self.pairing.device_id,
            _redact_notification(notification),
        )

        # Notification data may be nested under "data" key
        data = notification.get("data", notification)

        # ACK the notification for reliability
        fcm_message_id = (
            notification.get("fcmMessageId") or data.get("fcmMessageId") or persistent_id
        )
        notification_type = data.get("FermaxNotificationType", "")
        is_call = notification_type in ("Call", "CallAttend", "CallEnd")
        self.hass.async_create_task(self.api.ack_notification(fcm_message_id, is_call=is_call))

        # Start video stream based on call mode:
        # - Autoon (camera preview button): always start stream
        # - Call (doorbell): depends on call_mode setting
        room_id = data.get("RoomId")
        should_stream = room_id and (
            notification_type == "Autoon"
            or (notification_type == "Call" and self._call_mode != CALL_MODE_NOTIFY)
        )
        if should_stream:
            socket_url = data.get("SocketUrl", DEFAULT_SIGNALING_URL)
            if not _is_trusted_signaling_url(socket_url):
                _LOGGER.warning(
                    "Rejected untrusted signaling URL from notification: %s",
                    socket_url,
                )
                socket_url = DEFAULT_SIGNALING_URL
            fermax_token = data.get("FermaxToken", "")
            self.hass.async_create_task(self._start_stream(room_id, socket_url, fermax_token))
            if (
                notification_type == "Call"
                and self._call_mode == CALL_MODE_AUTO_RESPOND
                and self._auto_response_file
            ):
                self.hass.async_create_task(self._auto_respond())

        # Only trigger doorbell ring for actual calls, not auto-on
        if notification_type == "Call":
            self._doorbell_ringing = True
            self._photo_fetch_pending = True

            door_key = data.get("AccessDoorKey", data.get("accessDoorKey", "GENERAL"))
            async_dispatcher_send(
                self.hass,
                SIGNAL_DOORBELL_RING.format(self.pairing.device_id, door_key),
            )

            # Cancel previous reset timer if still pending
            if self._doorbell_reset_unsub:
                self._doorbell_reset_unsub()

            @callback
            def _reset_ringing(_now: Any) -> None:
                """Reset doorbell ringing state."""
                self._doorbell_ringing = False
                async_dispatcher_send(
                    self.hass,
                    SIGNAL_CALL_ENDED.format(self.pairing.device_id),
                )
                self.async_set_updated_data(self.data)
                self._doorbell_reset_unsub = None

            self._doorbell_reset_unsub = async_call_later(
                self.hass, DOORBELL_RESET_SECONDS, _reset_ringing
            )

            # Trigger a data refresh to get any new photos
            self.hass.async_create_task(self.async_request_refresh())

    async def open_door(self, door_name: str = "GENERAL") -> bool:
        """Open a specific door. Uses in-call endpoint if stream is active."""
        success = False

        # If there's an active stream, use the in-call endpoint
        if self._stream_session and self._stream_session.is_active:
            fcm_token = self.notification_listener.fcm_token if self.notification_listener else None
            success = await self.api.open_door_incall(
                device_id=self.pairing.device_id,
                room_id=self._stream_session._room_id,
                fcm_token=fcm_token,
                call_as=self.pairing.device_id,
            )
        else:
            door = self.pairing.access_doors.get(door_name)
            if not door:
                for d in self.pairing.access_doors.values():
                    door = d
                    break

            if not door:
                _LOGGER.error("No accessible door found for %s", door_name)
                return False

            success = await self.api.open_door(self.pairing.device_id, door.access_id)

        if success:
            async_dispatcher_send(
                self.hass,
                SIGNAL_DOOR_OPENED.format(self.pairing.device_id),
            )

        return success

    async def start_direct_stream(self, manual: bool = False) -> bool:
        """Start the persistent direct-LAN QUII stream session.

        Opens ONE connection to the videoporter and decodes H.264 → JPEG
        continuously (~20 fps) — no cloud, no FCM token needed.

        ``manual=True`` (the "Camera stream" switch) keeps the stream up until
        the user turns it off — the auto-stop timeout is skipped.
        """
        api = self.api
        if not getattr(api, "_device_ip", None):
            return False
        # Idempotent: already streaming → nothing to do.
        if self._direct_stream and self._direct_stream.is_active:
            if manual:
                self._direct_manual = True
            return True
        # The H.264→JPEG decode needs PyAV; fail loudly if it's missing so the
        # "no camera image" case is obvious instead of silent.
        try:
            import av  # noqa: F401
        except ImportError:
            _LOGGER.error(
                "PyAV (av) is not installed — the direct camera cannot decode "
                "the videoporter stream. Restart Home Assistant so the declared "
                "requirement av>=13.0.0 gets installed."
            )
            return False
        try:
            if not getattr(api, "_stream_key", ""):
                await api.get_stream_key_direct()
            from .direct_camera import CameraConfig, SeeuDirectStream

            cfg = CameraConfig(
                ip=api._device_ip,
                username=getattr(api, "_device_username", "adminapp2"),
                pin=getattr(api, "_device_pin", ""),
                auth_code=getattr(api, "_qr_auth_code", "") or "",
                stream_key=getattr(api, "_stream_key", "") or "",
                client_id=getattr(api, "_client_id", "") or "",
            )
            if self._direct_stream:
                self._direct_stream.stop()
            stream = SeeuDirectStream(cfg)
            # When the first frame is decoded the stream is really live — flip
            # the camera state to "Streaming" at that moment (not before, which
            # is why it used to show "Idle" while already streaming).
            stream.on_first_frame = self._notify_direct_stream_changed
            stream.start()
            self._direct_stream = stream
            self._camera_active = True
            if manual:
                self._direct_manual = True
            _LOGGER.info("Direct LAN stream started for %s", api._device_ip)
            self._notify_direct_stream_changed()
            # Bound its lifetime so the videoporter is freed for the phone app
            # if nobody actually watches the camera — UNLESS the user explicitly
            # turned the stream on via the "Camera stream" switch. The timeout
            # is the configured "Stream duration" (number entity, 10–120s).
            if not self._direct_manual:
                timeout = max(MIN_STREAM_DURATION, int(self._stream_duration))
                self._schedule_direct_stop(timeout)
            return True
        except Exception:
            _LOGGER.error("Failed to start direct LAN stream", exc_info=True)
            return False

    def direct_viewer_started(self) -> None:
        """A camera viewer (MJPEG consumer) began watching — keep the stream up."""
        self._direct_viewers += 1
        if self._direct_stop_unsub:
            self._direct_stop_unsub()
            self._direct_stop_unsub = None

    def direct_viewer_ended(self) -> None:
        """A camera viewer left; free the videoporter once the last one goes."""
        self._direct_viewers = max(0, self._direct_viewers - 1)
        if self._direct_viewers == 0:
            self._schedule_direct_stop(DIRECT_STREAM_VIEWER_GRACE)

    def _schedule_direct_stop(self, delay: float) -> None:
        """Schedule stopping the direct stream after ``delay`` seconds."""
        if self._direct_manual:
            return  # user explicitly turned the stream on — keep it up
        if self._direct_stop_unsub:
            return  # already scheduled

        @callback
        def _do_stop(_now: Any) -> None:
            self._direct_stop_unsub = None
            # Only stop if nobody started watching again in the meantime.
            if self._direct_viewers == 0 and self._direct_stream is not None:
                self.hass.async_create_task(self.stop_direct_stream())

        self._direct_stop_unsub = async_call_later(self.hass, delay, _do_stop)

    async def stop_direct_stream(self) -> None:
        """Stop the persistent direct-LAN stream session."""
        if self._direct_stop_unsub:
            self._direct_stop_unsub()
            self._direct_stop_unsub = None
        self._direct_viewers = 0
        self._direct_manual = False
        stream = self._direct_stream
        self._direct_stream = None
        if stream is not None:
            stream.stop()
            _LOGGER.info("Direct LAN stream stopped — videoporter freed")
        self._notify_direct_stream_changed()
        self._camera_active = False

    async def start_camera_preview(self) -> DivertResponse | None:
        """Start camera preview (auto-on) to view the intercom camera.

        For a direct LAN connection (See-U) this starts the persistent QUII
        stream — no cloud/FCM/pymediasoup needed.
        """
        if getattr(self.api, "_device_ip", None):
            # Toggle: pressing while already streaming stops it, so the user
            # can free the videoporter for the phone app from the same button.
            if self._direct_stream and self._direct_stream.is_active:
                await self.stop_direct_stream()
                return DivertResponse(
                    reason="direct",
                    divert_service="lan",
                    code=0,
                    description="Direct LAN stream stopped",
                    directed_to=self.api._device_ip or "",
                )
            ok = await self.start_direct_stream()
            if ok:
                return DivertResponse(
                    reason="direct",
                    divert_service="lan",
                    code=0,
                    description="Direct LAN stream started",
                    directed_to=self.api._device_ip or "",
                )
            return None

        if not self.notification_listener or not self.notification_listener.fcm_token:
            _LOGGER.error("Cannot start camera: no FCM token available")
            return None

        if not streaming_deps_available():
            _LOGGER.warning(
                "Camera preview unavailable: optional live-video dependencies "
                "(pymediasoup/aiortc) are not installed; skipping auto-on so the "
                "intercom is not woken up for a stream that cannot start"
            )
            return None

        result = await self.api.auto_on(
            self.pairing.device_id,
            self.notification_listener.fcm_token,
        )

        if result:
            self._camera_active = True

            _LOGGER.info(
                "Camera preview started: %s (%s)",
                result.reason,
                result.description,
            )

            # Cancel previous camera timeout if still pending
            if self._camera_timeout_unsub:
                self._camera_timeout_unsub()

            @callback
            def _deactivate_camera(_now: Any) -> None:
                """Deactivate camera after timeout."""
                self._camera_active = False
                self.async_set_updated_data(self.data)
                self._camera_timeout_unsub = None

            self._camera_timeout_unsub = async_call_later(
                self.hass, CAMERA_TIMEOUT_SECONDS, _deactivate_camera
            )
            self.async_set_updated_data(self.data)

        return result

    async def change_video_source(self) -> DivertResponse | None:
        """Request a video source change on the intercom."""
        if not self.notification_listener or not self.notification_listener.fcm_token:
            return None

        return await self.api.change_video_source(
            self.pairing.device_id,
            self.notification_listener.fcm_token,
        )

    async def set_dnd(self, enabled: bool) -> None:
        """Set Do Not Disturb."""
        if not self.notification_listener or not self.notification_listener.fcm_token:
            return
        await self.api.set_dnd(
            self.pairing.device_id,
            self.notification_listener.fcm_token,
            enabled=enabled,
        )
        self._dnd_enabled = enabled

    async def press_f1(self) -> None:
        """Press F1 auxiliary button."""
        await self.api.press_f1(self.pairing.device_id)

    async def call_guard(self) -> None:
        """Call the building guard."""
        await self.api.call_guard(self.pairing.device_id)

    async def set_photo_caller(self, enabled: bool) -> None:
        """Enable or disable photo caller."""
        await self.api.set_photo_caller(self.pairing.device_id, enabled=enabled)
        if self.device_info:
            self.device_info = replace(self.device_info, photocaller=enabled)

    async def _start_stream(self, room_id: str, signaling_url: str, fermax_token: str = "") -> None:
        """Start a video stream session for the given room."""
        if not streaming_deps_available():
            _LOGGER.warning(
                "Ignoring stream request for room %s: optional live-video "
                "dependencies (pymediasoup/aiortc) are not installed",
                room_id,
            )
            return

        await self.stop_stream()

        if not self.notification_listener:
            return
        fcm_token = self.notification_listener.fcm_token
        if not fcm_token:
            return
        oauth_token = fermax_token or await self.api.get_access_token()

        @callback
        def _on_stream_end() -> None:
            # Cancel auto-stop timer if still pending
            if self._stream_stop_unsub:
                self._stream_stop_unsub()
                self._stream_stop_unsub = None
            # Save last frame as photo preview before releasing the session
            if self._stream_session and self._stream_session.latest_frame:
                self._last_photo = self._stream_session.latest_frame
                self.hass.async_create_task(self._save_last_photo())
            self._stream_session = None
            self._camera_active = False
            self.async_set_updated_data(self.data)

        media_root = self.hass.config.media_dirs.get("local", "/media")
        self._stream_session = FermaxStreamSession(
            signaling_url=signaling_url,
            oauth_token=oauth_token,
            fcm_token=fcm_token,
            room_id=room_id,
            on_end=_on_stream_end,
            media_root=media_root,
        )

        success = await self._stream_session.start()
        if success:
            self._camera_active = True
            _LOGGER.info("Video stream started for room %s", room_id)
            async_dispatcher_send(self.hass, SIGNAL_CAMERA_ON.format(self.pairing.device_id))

            # Schedule auto-stop after configured duration
            @callback
            def _auto_stop_stream(_now: Any) -> None:
                _LOGGER.info("Stream auto-stop after %ds", self._stream_duration)
                self._stream_stop_unsub = None
                self.hass.async_create_task(self.stop_stream())

            self._stream_stop_unsub = async_call_later(
                self.hass, self._stream_duration, _auto_stop_stream
            )
        else:
            _LOGGER.warning("Failed to start video stream for room %s", room_id)
            self._stream_session = None

    async def _auto_respond(self) -> None:
        """Send auto-response audio after stream starts."""
        # Wait for stream to be ready
        for _ in range(20):
            if self._stream_session and self._stream_session.is_active:
                break
            await asyncio.sleep(0.5)
        if self._stream_session and self._stream_session.is_active:
            await asyncio.sleep(1)  # Extra delay for audio transport
            await self._stream_session.send_audio(self._auto_response_file)
            _LOGGER.info("Auto-response sent: %s", self._auto_response_file)

    async def stop_stream(self) -> None:
        """Stop the current video stream session (cloud and/or direct)."""
        await self.stop_direct_stream()
        if self._stream_session:
            # Save last frame before stopping (stop() may clear internal state)
            if self._stream_session.latest_frame:
                self._last_photo = self._stream_session.latest_frame
                self.hass.async_create_task(self._save_last_photo())
            await self._stream_session.stop()
            self._stream_session = None
            self._camera_active = False
