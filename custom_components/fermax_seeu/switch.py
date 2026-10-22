"""Switch platform for Fermax Blue."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_DIRECT_STREAM_CHANGED
from .coordinator import FermaxBlueCoordinator
from .entity import FermaxBlueEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Fermax Blue switches."""
    coordinators: list[FermaxBlueCoordinator] = hass.data[DOMAIN][entry.entry_id]
    entities: list[SwitchEntity] = []

    for coordinator in coordinators:
        if coordinator.notification_listener:
            entities.append(FermaxNotificationSwitch(coordinator))
        entities.append(FermaxDndSwitch(coordinator))
        entities.append(FermaxPhotoCallerSwitch(coordinator))
        # "Camera stream" toggle: only meaningful with a direct-LAN device.
        if getattr(coordinator.api, "_device_ip", None):
            entities.append(FermaxCameraStreamSwitch(coordinator))

    async_add_entities(entities)


class FermaxNotificationSwitch(FermaxBlueEntity, SwitchEntity):
    """Switch to enable/disable doorbell notifications."""

    _attr_translation_key = "notifications"

    def __init__(self, coordinator: FermaxBlueCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self._device_id}_notifications"
        self._is_on = True

    @property
    def is_on(self) -> bool:
        """Return True if notifications are enabled."""
        if self.coordinator.notification_listener:
            return self.coordinator.notification_listener.is_started
        return self._is_on

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable notifications."""
        if self.coordinator.notification_listener:
            await self.coordinator.notification_listener.start()
            self._is_on = True
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable notifications."""
        if self.coordinator.notification_listener:
            await self.coordinator.notification_listener.stop()
            self._is_on = False
            self.async_write_ha_state()


class FermaxDndSwitch(FermaxBlueEntity, SwitchEntity):
    """Switch for Do Not Disturb mode."""

    _attr_translation_key = "dnd"

    def __init__(self, coordinator: FermaxBlueCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self._device_id}_dnd"
        self._optimistic_state: bool | None = None

    @property
    def is_on(self) -> bool | None:
        """Return True if DND is enabled."""
        if self._optimistic_state is not None:
            return self._optimistic_state
        return self.coordinator.dnd_enabled

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable Do Not Disturb."""
        self._optimistic_state = True
        self.async_write_ha_state()
        await self.coordinator.set_dnd(True)
        self._optimistic_state = None

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable Do Not Disturb."""
        self._optimistic_state = False
        self.async_write_ha_state()
        await self.coordinator.set_dnd(False)
        self._optimistic_state = None


class FermaxPhotoCallerSwitch(FermaxBlueEntity, SwitchEntity):
    """Switch to enable/disable photo caller."""

    _attr_translation_key = "photo_caller"

    def __init__(self, coordinator: FermaxBlueCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self._device_id}_photo_caller"
        self._optimistic_state: bool | None = None

    @property
    def is_on(self) -> bool | None:
        """Return True if photo caller is enabled."""
        if self._optimistic_state is not None:
            return self._optimistic_state
        if self.coordinator.device_info:
            return self.coordinator.device_info.photocaller
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable photo caller."""
        self._optimistic_state = True
        self.async_write_ha_state()
        await self.coordinator.set_photo_caller(True)
        self._optimistic_state = None

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable photo caller."""
        self._optimistic_state = False
        self.async_write_ha_state()
        await self.coordinator.set_photo_caller(False)
        self._optimistic_state = None


class FermaxCameraStreamSwitch(FermaxBlueEntity, SwitchEntity):
    """Toggle for the direct-LAN live stream (See-U).

    Unlike the momentary "Camera preview" button, this is a proper on/off
    control: ON starts the stream and keeps it up until you switch it off
    (the videoporter's single connection is held deliberately). OFF stops it
    and frees the videoporter for the phone app.
    """

    _attr_translation_key = "camera_stream"

    def __init__(self, coordinator: FermaxBlueCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{self._device_id}_camera_stream"

    async def async_added_to_hass(self) -> None:
        """Keep the switch state in sync with the stream."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_DIRECT_STREAM_CHANGED.format(self._device_id),
                self._on_stream_changed,
            )
        )

    def _on_stream_changed(self) -> None:
        # The direct stream runs on a worker thread; whatever thread dispatches
        # this, always write state on the event loop (call_soon_threadsafe is
        # safe from any thread, including the loop itself).
        self.hass.loop.call_soon_threadsafe(self.async_write_ha_state)

    @property
    def is_on(self) -> bool:
        """True while the direct stream is active."""
        stream = self.coordinator.direct_stream
        return bool(stream and stream.is_active)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start the stream and keep it up until turned off."""
        await self.coordinator.start_direct_stream(manual=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the stream and free the videoporter."""
        await self.coordinator.stop_stream()
