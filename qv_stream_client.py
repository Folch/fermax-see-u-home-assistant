#!/usr/bin/env python3
"""Fermax See-U QV stream client (port 34567).

Reimplements the login protocol captured from the app:
  1. TCP connect to 192.168.1.145:34567
  2. Send 32-byte handshake: a9 00 00 00 ... 00 02 ...
  3. Send AES-256 encrypted login packet (208 bytes)
  4. Receive and decrypt stream packets

Usage:
    python3 qv_stream_client.py <device_ip> [pin]
"""

import hashlib
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# AES key from get.device.streamkey
AES_KEY = b"2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va"
# clientid prefix (002 = see-u, 4112 = app id)
CLIENT_ID_PREFIX = "002-4112-"


def sha256_hex_ascii(pin: str) -> str:
    """SHA256(pin) as lowercase hex ASCII string."""
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()


def aes_encrypt(data: bytes) -> bytes:
    """AES-256-CBC with null IV."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b"\x00" * 16))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_decrypt(data: bytes) -> bytes:
    """AES-256-CBC with null IV."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b"\x00" * 16))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def build_login(pin: str, client_id: str) -> bytes:
    """Build the 208-byte login packet (unencrypted payload)."""
    pwd_hex = sha256_hex_ascii(pin)

    # Header (32 bytes)
    header = (
        b"\x01" + os.urandom(1) + b"AZ" + b"0000" + b"\x80" + b"0" + b"\xb5"
        + b"0101" + b"\x01" + b"\x00" * 16
    )
    # Make it 32 bytes
    header = header[:32].ljust(32, b"\x00")

    # Nonce (8 random bytes)
    nonce = os.urandom(8)

    # Password hex-ascii + oemid + clientid
    payload = (
        pwd_hex.encode()
        + b"\x00"
        + b"G0112"
        + b"\x00"
        + f"clientid={client_id}".encode()
        + b"\x00"
    )

    # Token (32 bytes random)
    token = os.urandom(32)

    # Assemble: header + nonce + payload + token, pad to 208
    body = header + nonce + payload + token
    body = body.ljust(208, b"\x00")
    # Encrypt the whole 208-byte payload
    return aes_encrypt(body[:208])


def connect_and_login(ip: str, pin: str, client_id: str) -> socket.socket:
    """Connect and perform the handshake + login."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, 34567))
    print(f"[+] Connected to {ip}:34567")

    # Phase 1: handshake (32 bytes)
    handshake = (
        b"\xa9\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    s.sendall(handshake)
    print(f"[+] Sent handshake ({len(handshake)}B)")
    time.sleep(0.2)

    # Read handshake response
    try:
        resp = s.recv(64)
        print(f"[+] Handshake resp ({len(resp)}B): {resp.hex()}")
    except socket.timeout:
        print("[!] No handshake response")

    # Phase 2: login (208 bytes encrypted)
    login = build_login(pin, client_id)
    s.sendall(login)
    print(f"[+] Sent login ({len(login)}B)")

    return s


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 qv_stream_client.py <device_ip> [pin]")
        sys.exit(1)

    ip = sys.argv[1]
    pin = sys.argv[2] if len(sys.argv) > 2 else "1993"
    client_id = CLIENT_ID_PREFIX + hashlib.md5(ip.encode()).hexdigest()

    print(f"=== Fermax See-U QV Stream Client ===")
    print(f"IP        : {ip}")
    print(f"PIN       : {pin}")
    print(f"Client ID : {client_id}")
    print(f"AES Key   : {AES_KEY.decode()}")
    print()

    s = connect_and_login(ip, pin, client_id)
    s.settimeout(5)

    print("[+] Waiting for stream data (Ctrl+C to stop)...")
    try:
        while True:
            try:
                data = s.recv(2048)
                if not data:
                    print("[-] Connection closed by device")
                    break
                print(f"[+] Received {len(data)}B: {data[:32].hex()}...")
                # Try to decrypt
                if len(data) >= 16:
                    dec = aes_decrypt(data[: len(data) // 16 * 16])
                    printable = sum(1 for b in dec if 32 <= b < 127)
                    if printable > len(dec) * 0.5:
                        print(f"    decrypted (printable): {dec[:60]!r}")
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        print("\n[+] Stopped")
    finally:
        s.close()


if __name__ == "__main__":
    main()
