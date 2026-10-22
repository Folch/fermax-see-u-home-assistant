"""LAN discovery for Fermax See-U videoporter.

Finds the device on the local network by probing candidate IPs for a
device that answers the CGI endpoint (/tdkcgi) and matches the MAC
from the QR code.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass

import httpx

_LOGGER = logging.getLogger(__name__)


@dataclass
class DeviceDiscovery:
    """Result of a LAN discovery."""

    ip: str
    mac: str
    model: str
    version: str


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _build_status_xml(username: str, pin: str) -> str:
    """Build the get.device.status CGI XML."""
    pwd_hash = _sha256(pin)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<envelope>\n"
        "  <header>\n"
        "    <security>username</security>\n"
        f"    <username>{username}</username>\n"
        f"    <password>{pwd_hash}</password>\n"
        "    <passwordencode>1</passwordencode>\n"
        "  </header>\n"
        "  <body>\n"
        "    <command>get.device.status</command>\n"
        "    <content/>\n"
        "  </body>\n"
        "</envelope>"
    )


def _parse_device_status(xml_text: str) -> tuple[str, str] | None:
    """Extract MAC and model from a get.device.status response."""
    import re

    mac_match = re.search(r"<mac>([^<]+)</mac>", xml_text)
    model_match = re.search(r"<model>([^<]+)</model>", xml_text)
    version_match = re.search(r"<version>([^<]+)</version>", xml_text)
    if not mac_match:
        return None
    return (
        mac_match.group(1).strip().lower(),
        model_match.group(1).strip() if model_match else "",
    )


async def _probe_ip(
    ip: str,
    username: str,
    pin: str,
    expected_mac: str | None,
    client: httpx.AsyncClient,
) -> DeviceDiscovery | None:
    """Probe a single IP for the See-U device."""
    xml = _build_status_xml(username, pin)
    headers = {
        "Content-Type": "application/xml",
        "charset": "utf-8",
        "Accept": "application/xml",
    }
    url = f"https://{ip}/tdkcgi"
    try:
        resp = await client.post(url, headers=headers, content=xml)
        if resp.status_code != 200:
            return None
        parsed = _parse_device_status(resp.text)
        if not parsed:
            return None
        mac, model = parsed
        # If we know the expected MAC, require a match (allow None to skip check)
        if expected_mac and mac != expected_mac.replace(":", "").lower():
            return None
        version_match = __import__("re").search(r"<version>([^<]+)</version>", resp.text)
        version = version_match.group(1) if version_match else ""
        return DeviceDiscovery(ip=ip, mac=mac, model=model, version=version)
    except Exception:
        return None


async def discover_device(
    expected_mac: str | None = None,
    *,
    username: str = "adminapp2",
    pin: str = "1234",
    target_ip: str | None = None,
) -> DeviceDiscovery | None:
    """Discover the See-U device on the LAN.

    If ``target_ip`` is provided, probe just that IP. Otherwise scan the
    local /24 subnet (common private ranges).
    """
    if target_ip:
        candidates = [target_ip]
    else:
        candidates = []
        for subnet in ("192.168.1", "192.168.0", "10.0.0", "192.168.2", "192.168.10", "172.16.0"):
            candidates.extend(f"{subnet}.{host}" for host in range(1, 255))

    timeout = httpx.Timeout(3.0, connect=0.5)
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Probe candidates in small batches to avoid overwhelming the network
        for i in range(0, len(candidates), 20):
            batch = candidates[i : i + 20]
            results = await asyncio.gather(
                *(
                    _probe_ip(ip, username, pin, expected_mac, client)
                    for ip in batch
                )
            )
            for res in results:
                if res is not None:
                    _LOGGER.info("Found See-U device at %s (mac=%s)", res.ip, res.mac)
                    return res
    return None
