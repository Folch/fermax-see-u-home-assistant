"""Camera platform for Fermax Blue / See-U."""

from __future__ import annotations

import asyncio
import logging
import time

from aiohttp import web
from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_DEVICE_IP,
    DOMAIN,
    SIGNAL_DIRECT_STREAM_CHANGED,
    SIGNAL_DOORBELL_RING,
)
from .coordinator import FermaxBlueCoordinator
from .entity import FermaxBlueEntity
from .streaming import streaming_deps_available

_LOGGER = logging.getLogger(__name__)

# The dashboard polls async_camera_image regularly; caching the snapshot avoids
# opening a new connection to the videoporter on every poll (it only accepts
# one viewer — polling would make the device look "busy" to the phone app).
SNAPSHOT_CACHE_SECONDS = 30


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Fermax Blue cameras."""
    coordinators: list[FermaxBlueCoordinator] = hass.data[DOMAIN][entry.entry_id]
    entities: list[Camera] = []

    for coordinator in coordinators:
        entities.append(FermaxCamera(coordinator))

    async_add_entities(entities)


class FermaxCamera(FermaxBlueEntity, Camera):
    """Camera entity with live video streaming and visitor photo capture.

    Supports two modes:
    - Still image: shows the last captured visitor photo (from doorbell ring)
    - Live stream: connects to the intercom camera via mediasoup and serves
      MJPEG frames in real-time (triggered by turn_on / camera preview button)
    """

    _attr_translation_key = "visitor"

    def __init__(self, coordinator: FermaxBlueCoordinator) -> None:
        FermaxBlueEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._attr_unique_id = f"{self._device_id}_camera"
        self._snapshot_cache: bytes | None = None
        self._snapshot_at = 0.0

    async def async_added_to_hass(self) -> None:
        """Register for doorbell ring events."""
        await super().async_added_to_hass()
        self.async_on_remove(self._cleanup_direct_stream)

        # Keep the entity state in sync when the direct stream starts/stops
        # (otherwise it would keep showing "Streaming" long after the stream
        # was freed for the phone app).
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_DIRECT_STREAM_CHANGED.format(self._device_id),
                self._on_direct_stream_changed,
            )
        )

        for door_name in self.coordinator.pairing.access_doors:
            self.async_on_remove(
                async_dispatcher_connect(
                    self.hass,
                    SIGNAL_DOORBELL_RING.format(self._device_id, door_name),
                    self._on_doorbell_ring,
                )
            )

        # Force state update so HA knows we have an image immediately
        if self.coordinator.last_photo:
            self.async_write_ha_state()

    @callback
    def _on_doorbell_ring(self) -> None:
        """Handle doorbell ring - trigger image refresh."""
        self.async_write_ha_state()

    @callback
    def _on_direct_stream_changed(self) -> None:
        """Direct stream started/stopped — refresh the entity state.

        The stream thread may trigger this; always write state on the loop.
        """
        self.hass.loop.call_soon_threadsafe(self.async_write_ha_state)

    @property
    def available(self) -> bool:
        """Camera is available if we have any image to serve."""
        if self.coordinator.last_photo:
            return True
        direct = self.coordinator.direct_stream
        if direct and direct.latest_frame:
            return True
        stream = self.coordinator.stream_session
        if stream and stream.latest_frame:
            return True
        return super().available

    async def async_camera_image(
        self,
        width: int | None = None,  # noqa: V107
        height: int | None = None,  # noqa: V107
    ) -> bytes | None:
        """Return the latest frame.

        For See-U direct connection, if a live stream is already active (the
        user is watching), return its latest frame instantly. Otherwise take a
        one-shot snapshot over the LAN — we deliberately do NOT open a
        persistent stream here, because the videoporter accepts only one
        viewer at a time and the phone app must keep working.
        """
        # Active persistent stream: instant, fluid (~20 fps). Keep the cache
        # fresh from live frames too.
        direct = self.coordinator.direct_stream
        if direct and direct.latest_frame:
            self._snapshot_cache = direct.latest_frame
            self._snapshot_at = time.time()
            # State write lets HA flip the entity to available once we have
            # a frame (the frontend otherwise keeps showing "Unavailable").
            self.async_write_ha_state()
            return direct.latest_frame

        api = getattr(self.coordinator, "api", None)
        device_ip = getattr(api, "_device_ip", None)
        if device_ip:
            # Serve the cached snapshot while it's fresh — do NOT open a new
            # connection to the videoporter on every dashboard poll.
            now = time.time()
            if self._snapshot_cache and (now - self._snapshot_at) < SNAPSHOT_CACHE_SECONDS:
                return self._snapshot_cache

            # A one-shot snapshot needs the QUII stream key to decrypt; fetch
            # it on demand so the preview is never a broken image (previously
            # the key was only fetched when the stream started).
            if not getattr(api, "_stream_key", ""):
                try:
                    await api.get_stream_key_direct()
                except Exception:
                    _LOGGER.debug("Could not fetch stream key for snapshot", exc_info=True)
            try:
                from .direct_camera import CameraConfig, capture_frame

                cfg = CameraConfig(
                    ip=device_ip,
                    username=getattr(api, "_device_username", "adminapp2"),
                    pin=getattr(api, "_device_pin", ""),
                    auth_code=getattr(api, "_qr_auth_code", "") or "",
                    stream_key=getattr(api, "_stream_key", "") or "",
                    client_id=getattr(api, "_client_id", "") or "",
                )
                jpeg = await asyncio.to_thread(capture_frame, cfg, 8.0)
                if jpeg:
                    self._snapshot_cache = jpeg
                    self._snapshot_at = time.time()
                    return jpeg
            except Exception:
                _LOGGER.debug("Direct camera capture failed", exc_info=True)
            # Fall back to the last cached snapshot so the card is never broken.
            if self._snapshot_cache:
                return self._snapshot_cache

        stream = self.coordinator.stream_session
        if stream and stream.latest_frame:
            return stream.latest_frame
        return self.coordinator.last_photo

    async def async_handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse | None:
        """Serve MJPEG stream: live frames when streaming, last photo otherwise.

        Modern HA cameras expose this method so the frontend's camera card
        plays the stream directly — opening the "Visitor" camera starts the
        direct-LAN stream automatically (no need to press the preview button).

        The stream serves continuously — when a live stream starts or stops,
        the MJPEG output switches seamlessly between live frames and the
        static preview without dropping the connection.
        """
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "multipart/x-mixed-replace;boundary=frameboundary",
            },
        )
        await response.prepare(request)

        # This card is a PASSIVE renderer: it never starts the stream by
        # itself. The videoporter accepts only one viewer, so the phone app
        # must keep working when nobody is watching. The card serves live
        # frames while a stream is active, otherwise the cached snapshot.
        # Starting/stopping is driven by the "Camera preview" button (toggle)
        # and the configured Stream duration timeout.
        try:
            while True:
                stream = self.coordinator.stream_session
                direct = self.coordinator.direct_stream
                frame = None

                # Prefer live stream frame (direct LAN first, then cloud)
                if direct and direct.latest_frame:
                    frame = direct.latest_frame
                elif stream and stream.latest_frame:
                    frame = stream.latest_frame
                else:
                    # Static snapshot — never a broken/black image.
                    frame = self._snapshot_cache or self.coordinator.last_photo

                if frame:
                    await response.write(
                        b"--frameboundary\r\n"
                        b"Content-Type: image/jpeg\r\n"
                        b"Content-Length: "
                        + str(len(frame)).encode()
                        + b"\r\n\r\n"
                        + frame
                        + b"\r\n"
                    )

                # Fast poll while a stream exists (so live frames are picked up
                # as soon as they start), slow poll for a purely static preview.
                if direct is not None or (stream and stream.is_active):
                    await asyncio.sleep(0.04)  # ~25fps
                else:
                    await asyncio.sleep(2)  # Refresh preview every 2s
        except (ConnectionResetError, ConnectionError, asyncio.CancelledError):
            pass

        return response

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse | None:
        """Legacy alias for async_handle_async_mjpeg_stream."""
        return await self.async_handle_async_mjpeg_stream(request)

    async def async_turn_on(self) -> None:
        """Start live camera stream.

        The coordinator's start_camera_preview() handles both paths: a
        persistent direct-LAN QUII stream for See-U (no cloud), or the cloud
        auto-on + mediasoup flow otherwise.
        """
        if not streaming_deps_available() and not getattr(
            getattr(self.coordinator, "api", None), "_device_ip", None
        ):
            _LOGGER.warning(
                "Live video is unavailable for %s: optional streaming "
                "dependencies (pymediasoup/aiortc) are not installed",
                self.entity_id,
            )
            return

        result = await self.coordinator.start_camera_preview()
        if result:
            _LOGGER.info("Camera auto-on started: %s", result.description)
        else:
            _LOGGER.error("Failed to start camera auto-on")

    def _cleanup_direct_stream(self) -> None:
        """Stop the direct stream on entity removal."""
        self.hass.async_create_task(self.coordinator.stop_direct_stream())

    async def async_turn_off(self) -> None:
        """Stop live camera stream."""
        await self.coordinator.stop_stream()

    @property
    def is_streaming(self) -> bool:
        """Return True if live video stream is active."""
        direct = self.coordinator.direct_stream
        if direct and direct.is_active:
            return True
        stream = self.coordinator.stream_session
        return bool(stream and stream.is_active)

    @property
    def is_on(self) -> bool:
        """Return True if the camera can serve an image."""
        if self.is_streaming:
            return True
        return self.coordinator.last_photo is not None

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Expose the live-stream status so a card can show "Starting...".

        idle      — no stream (snapshot only)
        starting  — stream connecting, first frame not yet decoded
        streaming — live frames flowing
        """
        direct = self.coordinator.direct_stream
        if direct is None:
            status = "idle"
        elif direct.is_active:
            status = "streaming"
        elif direct._connecting:
            status = "starting"
        else:
            status = "idle"
        return {"stream_status": status}
