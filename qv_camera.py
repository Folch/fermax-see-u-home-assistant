#!/usr/bin/env python3
"""Fermax See-U camera client (port 34567).

Captures the H.264 video stream from the videoporter and saves raw
H.264 frames to a file (or decodes them if PyAV/ffmpeg is available).

Usage:
    python3 qv_camera.py <device_ip> [output.h264]
"""

import hashlib
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# AES key from get.device.streamkey (captured)
AES_KEY = b"2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va"

# The captured login packet (works with the device)
# Reconstruct from the known plaintext structure
STREAM_PWD = "24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2"
CLIENT_ID = "clientid=002-4112-7F950C009611492F8C4D9D73FBC56215"


def aes_decrypt(data: bytes) -> bytes:
    """AES-256-CBC with null IV."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b"\x00" * 16))
    d = cipher.decryptor()
    return d.update(data) + d.finalize()


def aes_encrypt(data: bytes) -> bytes:
    """AES-256-CBC with null IV."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b"\x00" * 16))
    e = cipher.encryptor()
    return e.update(data) + e.finalize()


# Fixed nonce/token from the captured working session.
# These are session values that the device verifies.
FIXED_NONCE = bytes.fromhex("7032761dc2dfa544adbe7e9b532bdc2f")
FIXED_TOKEN = bytes.fromhex(
    "57efac413c086567725de1c1a0663feef50c6b784ad24fc17501c107"
)


def build_login() -> bytes:
    """Build the 208-byte login packet (encrypted).

    Layout (verified from capture):
        offset 0-17:   header "1O\xddAZ0000\x800\xb50101\x01" (17 bytes)
        offset 17-32:  15 zero bytes
        offset 32-48:  nonce (16 bytes)
        offset 48-108: password (60 bytes: 59 hex + \x00)
        offset 108-113: "G0112" (5 bytes)
        offset 113:    \x00
        offset 114-165: "clientid=002-4112-...\x00"
        offset 165-168: \x1b!< (3 bytes)
        offset 168-200: token (32 bytes)
        offset 200-208: zeros
    """
    header = bytes.fromhex("314fdd415a303030308030b53031303101")  # 17B
    nonce = FIXED_NONCE
    pwd = STREAM_PWD.encode() + b"\x00"
    g0112 = b"G0112"
    sep = b"\x00"
    cid = CLIENT_ID.encode() + b"\x00"
    mid = bytes.fromhex("1b213c")
    token = FIXED_TOKEN
    body = (
        header
        + b"\x00" * 15
        + nonce
        + pwd
        + g0112
        + sep
        + cid
        + mid
        + token
    )
    body = body[:208].ljust(208, b"\x00")
    return aes_encrypt(body)


# The exact encrypted login captured from the app (verified working).
# The device accepts this byte-for-byte even if nonce/token are session-bound.
EXACT_LOGIN_HEX = (
    "2d962b95a5e0d7b4e771bb80712704df21662b449c8ee504afa86893062cdd7d"
    "7c9a2269adccd484daed3424507edb3d06c9be428c2ffc5fd8eb6d2d3da07cf4"
    "c382c6f3deb9d37c5b6ff94ab7d992f28e29bba2d020bf6189641bfdbe425055"
    "b278026800534c7d8022dc1722a98d6e33265ef54aa5edc573046d6767d826408"
    "67b2a6ab10968362c6cd01b09dc21425f1ff4b0e0da9d9ace2e5b24d824f9a98"
    "8b2080cb8a5bdff95eee541a29c3563519cb0dd233f92ef62e95ac082e3cf8e6"
    "9580bfe6e4948be0637172194622f49"
)

EXACT_HANDSHAKE_HEX = (
    "a900000000000000000000000000000000000000000000000000000000000000"
)


def extract_h264(data: bytes) -> list[bytes]:
    """Extract H.264 frames (NAL units) from the decrypted stream."""
    # Remove QV protocol headers. Each QV packet has a header like:
    # [seq2B] "AZ0000" ... then payload. The H.264 NALs are embedded.
    nals = []
    i = 0
    start_codes = (b"\x00\x00\x00\x01", b"\x00\x00\x01")
    while i < len(data):
        # find next start code
        idx = -1
        sc_len = 0
        for sc in start_codes:
            j = data.find(sc, i)
            if j >= 0 and (idx < 0 or j < idx):
                idx = j
                sc_len = len(sc)
        if idx < 0:
            break
        # find end of this NAL
        end = len(data)
        for sc in start_codes:
            j = data.find(sc, idx + sc_len)
            if j >= 0 and j < end:
                end = j
        nal = data[idx:end]
        if len(nal) > 4:
            nals.append(nal)
        i = end if end > idx else idx + 1
    return nals


def connect_and_capture(ip: str, duration: float = 5.0) -> bytes:
    """Connect, login, and capture raw stream."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, 34567))

    # Handshake (exact captured bytes)
    handshake = bytes.fromhex(EXACT_HANDSHAKE_HEX)
    s.sendall(handshake)
    time.sleep(0.3)
    try:
        hs = s.recv(64)
        print(f"[+] Handshake resp: {hs.hex()[:32]}...")
    except socket.timeout:
        print("[!] No handshake response")

    # Login (exact captured encrypted bytes — verified working)
    login = bytes.fromhex(EXACT_LOGIN_HEX)
    s.sendall(login)
    print(f"[+] Sent login ({len(login)}B, exact captured bytes)")

    # Capture stream
    stream = b""
    start = time.time()
    while time.time() - start < duration:
        try:
            r = s.recv(65536)
            if not r:
                break
            stream += r
        except socket.timeout:
            break
    s.close()
    return stream


def h264_to_jpeg(h264_data: bytes) -> bytes | None:
    """Decode H.264 to a JPEG image using PyAV."""
    import io

    try:
        import av
    except ImportError:
        print("[-] PyAV not available. Install with: pip3 install av")
        return None

    try:
        container = av.open(io.BytesIO(h264_data), format="h264")
        for frame in container.decode(video=0):
            img = frame.to_image()
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            return buf.getvalue()
    except Exception as e:
        print(f"[-] H.264 decode failed: {e}")
        return None
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 qv_camera.py <device_ip> [output.h264]")
        sys.exit(1)
    ip = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "stream.h264"

    print(f"=== Fermax See-U Camera ===")
    print(f"IP: {ip}")
    print(f"Connecting...")

    raw = connect_and_capture(ip, duration=8.0)
    print(f"[+] Captured {len(raw)}B raw stream")

    if not raw:
        print("[-] No stream received. The session nonce/token may be stale.")
        sys.exit(1)

    # Decrypt
    dec = aes_decrypt(raw[: len(raw) // 16 * 16])
    print(f"[+] Decrypted {len(dec)}B")

    # Extract H.264
    nals = extract_h264(dec)
    print(f"[+] Extracted {len(nals)} H.264 NAL units")

    if nals:
        # Write concatenated NALs
        with open(out, "wb") as f:
            for nal in nals:
                f.write(nal)
        print(f"[+] Saved H.264 to {out} ({sum(len(n) for n in nals)}B)")

        # Show NAL types
        for nal in nals[:10]:
            if len(nal) >= 5:
                nal_type = nal[4] & 0x1F
                print(f"    NAL type {nal_type} ({len(nal)}B)")

        # Try to decode to JPEG
        h264_bytes = b"".join(nals)
        jpeg = h264_to_jpeg(h264_bytes)
        if jpeg:
            jpeg_out = out.replace(".h264", ".jpg")
            with open(jpeg_out, "wb") as f:
                f.write(jpeg)
            print(f"[+] Saved JPEG to {jpeg_out} ({len(jpeg)}B)")
    else:
        print("[-] No H.264 frames found")
        # Save raw decrypted for analysis
        with open(out + ".raw", "wb") as f:
            f.write(dec)
        print(f"[+] Saved raw decrypted to {out}.raw")


if __name__ == "__main__":
    main()
