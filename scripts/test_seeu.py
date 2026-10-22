#!/usr/bin/env python3
"""Test script for Fermax See-U API connectivity.

Usage:
    python scripts/test_seeu.py <qr_json>

Example:
    python scripts/test_seeu.py '{"v":1,"u":"25025kt9aysi","c":"VKMFNOIO","m":"IDS94C3W","a":"IDS94C3Waysi","d":"b0211111","b":"e8:5c:5f:a0:2b:d8"}'
"""

import asyncio
import json
import sys
import httpx
import base64
from typing import Any


async def test_seeu_api(qr_data: dict[str, Any]) -> None:
    """Test Fermax See-U API with QR data."""
    
    auth_url = "https://oauth-pro-duoxme.fermax.io"
    base_url = "https://pro-duoxme.fermax.io"
    auth_basic = "ZHB2N2lxejZlZTVtYXptMWlxOWR3MWQ0MnNseXV0NDhrajBtcDVmdm81OGo1aWg6Yzd5bGtxcHVqd2FoODV1aG5wcnYwd2R2eXp1dGxjbmt3NHN6OTBidWxkYnVsazE="
    
    # Decode OAuth basic to see what we're using
    decoded = base64.b64decode(auth_basic).decode()
    print(f"\n🔐 OAuth Credentials (decoded):")
    print(f"   {decoded}")
    
    print(f"\n📱 QR Data:")
    print(f"   User ID (u): {qr_data.get('u')}")
    print(f"   Account ID (a): {qr_data.get('a')}")
    print(f"   Device ID (d): {qr_data.get('d')}")
    print(f"   MAC (b): {qr_data.get('b')}")
    print(f"   Model (m): {qr_data.get('m')}")
    print(f"   Code (c): {qr_data.get('c')}")
    
    async with httpx.AsyncClient(timeout=10) as client:
        print("\n" + "=" * 60)
        print("Testing Fermax See-U API Endpoints")
        print("=" * 60)
        
        # Test 1: Client credentials (server-to-server)
        print("\n[Test 1] OAuth client_credentials grant")
        try:
            resp = await client.post(
                f"{auth_url}/oauth/token",
                headers={
                    "Authorization": f"Basic {auth_basic}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={"grant_type": "client_credentials"},
            )
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                print(f"   ✅ Token: {token[:50]}...")
                test_token = token
            else:
                print(f"   ❌ Error: {resp.json().get('error_description', resp.text)}")
                test_token = None
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            test_token = None
        
        # Test 2: Password grant with User ID
        print("\n[Test 2] OAuth password grant with User ID")
        try:
            resp = await client.post(
                f"{auth_url}/oauth/token",
                headers={
                    "Authorization": f"Basic {auth_basic}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "grant_type": "password",
                    "username": qr_data['u'],
                    "password": qr_data['u']  # Try User ID as password
                },
            )
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                print(f"   ✅ Token: {token[:50]}...")
                test_token = token
            else:
                print(f"   ❌ Error: {resp.json().get('error_description', resp.text)}")
        except Exception as e:
            print(f"   ❌ Exception: {e}")
        
        # Test 3: If we have a token, try to get pairings
        if test_token:
            print("\n[Test 3] GET /pairing/api/v4/pairings/me")
            try:
                resp = await client.get(
                    f"{base_url}/pairing/api/v4/pairings/me",
                    headers={
                        "Authorization": f"Bearer {test_token}",
                        "Content-Type": "application/json"
                    },
                )
                print(f"   Status: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"   ✅ Pairings found: {resp.text[:200]}")
                else:
                    print(f"   ❌ Error: {resp.text[:200]}")
            except Exception as e:
                print(f"   ❌ Exception: {e}")
        
        # Test 4: Try direct QR pairing endpoint
        print("\n[Test 4] POST /pairing/api/v4/pairings (QR registration)")
        try:
            resp = await client.post(
                f"{base_url}/pairing/api/v4/pairings",
                headers={
                    "Content-Type": "application/json",
                },
                json={
                    "user_id": qr_data['u'],
                    "installation_id": qr_data['a'],
                    "device_id": qr_data['d'],
                    "mac": qr_data['b']
                },
            )
            print(f"   Status: {resp.status_code}")
            print(f"   Response: {resp.text[:300]}")
        except Exception as e:
            print(f"   ❌ Exception: {e}")


async def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python scripts/test_seeu.py '<qr_json>'")
        print("\nExample QR data:")
        print('  {"v":1,"u":"25025kt9aysi","c":"VKMFNOIO","m":"IDS94C3W","a":"IDS94C3Waysi","d":"b0211111","b":"e8:5c:5f:a0:2b:d8"}')
        sys.exit(1)
    
    qr_json = sys.argv[1]
    try:
        qr_data = json.loads(qr_json)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        sys.exit(1)
    
    await test_seeu_api(qr_data)


if __name__ == "__main__":
    asyncio.run(main())
