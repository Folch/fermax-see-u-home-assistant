#!/usr/bin/env python3
"""Parse and validate QR data from Fermax See-U integration."""

import json
import sys
from pathlib import Path


def parse_qr(qr_json_str: str) -> dict:
    """Parse and validate QR JSON string."""
    try:
        qr_data = json.loads(qr_json_str)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format - {e}")
        sys.exit(1)

    # Validate required fields
    required_fields = ["u", "a", "d", "b"]  # user_id, account_id, device_id, mac
    missing_fields = [field for field in required_fields if field not in qr_data]
    
    if missing_fields:
        print(f"Error: Missing required fields - {missing_fields}")
        sys.exit(1)

    # Display parsed data
    print("✓ Valid QR data parsed:")
    print(f"  User ID (u):     {qr_data.get('u')}")
    print(f"  Account ID (a):  {qr_data.get('a')}")
    print(f"  Device ID (d):   {qr_data.get('d')}")
    print(f"  MAC Address (b): {qr_data.get('b')}")
    print(f"  Model (m):       {qr_data.get('m', 'N/A')}")
    print(f"  Code (c):        {qr_data.get('c', 'N/A')}")
    print(f"  Version (v):     {qr_data.get('v', 'N/A')}")

    return qr_data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_qr.py '<qr_json_string>'")
        print()
        print("Example:")
        print('  parse_qr.py \'{"v":1,"u":"25025kt9aysi","c":"VKMFNOIO","m":"IDS94C3W","a":"IDS94C3Waysi","d":"b0211111","b":"e8:5c:5f:a0:2b:d8"}\'')
        sys.exit(1)

    qr_json = sys.argv[1]
    parse_qr(qr_json)
