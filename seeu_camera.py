#!/usr/bin/env python3
"""Fermax See-U camera: capture a JPEG frame from the videoporter.

Combines:
  - The exact captured QUII login that the device accepts (replay works)
  - The quii-lan-client protocol parser (IV = ASCII '0', framing 32B)

Requires: cryptography, av (PyAV), pillow. The quii-lan-client repo
must be present (or copy the quii_lan/ modules next to this script).

Usage:
    python3 seeu_camera.py <device_ip> [output.jpg]
"""

import hashlib
import io
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- QUII protocol constants (from quii-lan-client) ---
AES_KEY = b"2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va"  # get.device.streamkey <key>
IV = b"0" * 16  # ASCII zeros
MSG_HDR = 0x20  # 32 bytes

# The captured login packet that the device accepts (replay works).
# Contains: header + password(SHA256-ish) + G0112 + clientid + nonce + token.
CAPTURED_LOGIN_HEX = (
    "2d962b95a5e0d7b4e771bb80712704df21662b449c8ee504afa86893062cdd7d"
    "7c9a2269adccd484daed3424507edb3d06c9be428c2ffc5fd8eb6d2d3da07cf4"
    "c382c6f3deb9d37c5b6ff94ab7d992f28e29bba2d020bf6189641bfdbe425055"
    "b278026800534c7d8022dc1722a98d6e33265ef54aa5edc573046d6767d826408"
    "67b2a6ab10968362c6cd01b09dc21425f1ff4b0e0da9d9ace2e5b24d824f9a98"
    "8b2080cb8a5bdff95eee541a29c3563519cb0dd233f92ef62e95ac082e3cf8e6"
    "9580bfe6e4948be0637172194622f49"
)


def aes_decrypt(data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV))
    d = cipher.decryptor()
    return d.update(data) + d.finalize()


def recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def media_body_len(hdr: bytes) -> int:
    if len(hdr) < 0x0F:
        return 0
    u32 = struct.unpack_from("<I", hdr, 0x0B)[0]
    u16 = struct.unpack_from("<H", hdr, 0x0B)[0]
    if 0 < u32 <= 2_000_000:
        return u32
    if 0 < u16 <= 0xFFFF:
        return u16
    return struct.unpack_from("<H", hdr, 9)[0]


def unpack_media_payload(clear_hdr: bytes, body_ct: bytes) -> bytes:
    """Decrypt the media payload like PackFrame does."""
    param9 = struct.unpack_from("<H", clear_hdr, 9)[0]
    media_flag = clear_hdr[0x0F]
    off10 = struct.unpack_from("<H", clear_hdr, 0x10)[0]

    body = body_ct
    if param9 >= 1 and len(body) >= param9 and param9 % 16 == 0:
        head = aes_decrypt(body[:param9])
        body = head + body[param9:]

    if media_flag != 0:
        start = min(off10, len(body))
        media_ct = body[start:]
        aligned = len(media_ct) - (len(media_ct) % 16)
        if aligned > 0:
            pt = aes_decrypt(media_ct[:aligned])
            body = body[:start] + pt + media_ct[aligned:]

    if off10 and off10 < len(body):
        return body[off10:]
    return body


def find_keyframe(payload: bytes) -> bytes | None:
    """Return the H.264 data starting from the first keyframe marker."""
    for needle in (
        b"\x00\x00\x00\x01\x67",
        b"\x00\x00\x00\x01\x27",
        b"\x00\x00\x01\x67",
        b"\x00\x00\x01\x27",
    ):
        i = payload.find(needle)
        if i >= 0:
            return payload[i:]
    # fallback: any annex-b NAL
    for sc in (b"\x00\x00\x00\x01", b"\x00\x00\x01"):
        i = payload.find(sc)
        if i >= 0:
            return payload[i:]
    return None


def h264_to_jpeg(h264_data: bytes) -> bytes | None:
    """Decode H.264 to JPEG using PyAV."""
    import av
    try:
        container = av.open(io.BytesIO(h264_data), format="h264")
        for frame in container.decode(video=0):
            img = frame.to_image()
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            return buf.getvalue()
    except Exception:
        return None
    return None


def capture_frame(ip: str, duration: float = 10.0) -> bytes | None:
    """Connect, play, capture media, return a JPEG frame."""
    s = socket.create_connection((ip, 34567), 5)
    s.settimeout(2.0)
    try:
        # Setup
        setup = bytearray(MSG_HDR)
        setup[0] = 0xA9
        s.sendall(bytes(setup))
        setup_rx = recv_exact(s, MSG_HDR, 4.0)
        if len(setup_rx) < MSG_HDR or setup_rx[0] != 0xA9:
            return None
        enc_mode = setup_rx[0x0A]
        print(f"[+] Setup ok enc_mode={enc_mode}")

        # Play (exact captured login)
        login = bytes.fromhex(CAPTURED_LOGIN_HEX)
        s.sendall(login)
        print(f"[+] Sent play ({len(login)}B)")

        # Capture media
        data = bytearray()
        deadline = time.time() + duration
        while len(data) < 200_000 and time.time() < deadline:
            s.settimeout(1.5)
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                break
            data.extend(chunk)

        # Parse media packets for a keyframe
        pos = 0
        while pos + MSG_HDR <= len(data):
            wire_hdr = data[pos : pos + MSG_HDR]
            hdr = aes_decrypt(wire_hdr)
            cmd = hdr[0]
            if 0xA0 <= cmd <= 0xA3:
                body_len = media_body_len(hdr)
                total = MSG_HDR + body_len
                if pos + total > len(data):
                    break
                body_ct = data[pos + MSG_HDR : pos + total]
                payload = unpack_media_payload(hdr, body_ct)
                h264 = find_keyframe(payload)
                if h264 and len(h264) > 32:
                    jpeg = h264_to_jpeg(h264)
                    if jpeg:
                        return jpeg
                pos += total
            else:
                param_len = struct.unpack_from("<H", hdr, 9)[0]
                pos += MSG_HDR + param_len
        return None
    finally:
        s.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 seeu_camera.py <device_ip> [output.jpg]")
        sys.exit(1)
    ip = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "camera_frame.jpg"

    print(f"=== Fermax See-U Camera ===")
    print(f"IP: {ip}")
    jpeg = capture_frame(ip, duration=12.0)

    if jpeg:
        with open(out, "wb") as f:
            f.write(jpeg)
        print(f"✅ JPEG saved to {out} ({len(jpeg)}B)")
        return 0
    print("❌ No frame captured")
    return 1


if __name__ == "__main__":
    sys.exit(main())
