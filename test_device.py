#!/usr/bin/env python3
"""Test direct connection to the Fermax See-U videoporter on the LAN."""

import asyncio
import hashlib
import json
import sys

import httpx


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


async def test_device():
    """Test direct CGI connection to the videoporter."""
    print("Testing direct connection to videoporter 192.168.1.145...")
    print("=" * 60)

    # Credentials from captured traffic
    username = "adminapp2"
    password_hash = sha256_hex("1993")  # SHA256 of the PIN

    print(f"Username: {username}")
    print(f"Password (SHA256 of 1993): {password_hash}")
    print()

    # The XML from the captured traffic
    xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<envelope>
  <header>
    <security>username</security>
    <username>{username}</username>
    <password>{password_hash}</password>
    <passwordencode>1</passwordencode>
  </header>
  <body>
    <command>get.device.status</command>
    <content/>
  </body>
</envelope>'''

    # Try both HTTP and HTTPS, on different ports
    urls = [
        "https://192.168.1.145/tdkcgi",
        "http://192.168.1.145/tdkcgi",
        "https://192.168.1.145:443/tdkcgi",
        "http://192.168.1.145:80/tdkcgi",
        "https://192.168.1.145:8443/tdkcgi",
    ]

    headers = {
        "Content-Type": "application/xml",
        "charset": "utf-8",
        "Accept": "application/xml",
        "User-Agent": "SeeU/1.0.4.6 (com.fermax.seeu; iOS 14.0)",
    }

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for url in urls:
            print(f"[get.device.status] POST {url}")
            try:
                resp = await client.post(url, headers=headers, content=xml_payload)
                print(f"  Status: {resp.status_code}")
                print(f"  Body: {resp.text[:800]}")
                print()
            except Exception as e:
                print(f"  Exception: {type(e).__name__}: {e}")
                print()

    return None


async def main():
    await test_device()


if __name__ == "__main__":
    asyncio.run(main())