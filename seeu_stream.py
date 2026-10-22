#!/usr/bin/env python3
"""Fermax See-U persistent live-video stream session (QUII protocol, port 34567).

Keeps ONE TCP connection open to the videoporter: setup + play once, then
parses media packets continuously, decodes H.264 → JPEG with PyAV, and
publishes frames to subscribers. Sends keepalive every ~8s and reconnects
if the stream stalls or the device drops the connection.

This is what makes live video *fluid*: the old approach opened a fresh
connection per frame (setup + play + wait-for-keyframe ≈ 5s per picture).
Here the connection is long-lived, so frames stream at the device's native
~20fps instead of one picture every 5 seconds.

Requirements: cryptography, av (PyAV).

The play packet is built dynamically from the device PIN:
    body = adminapp2 && SHA256(PIN) \\0 G0112 \\0 clientid=... \\0 <token>
with a fixed device timestamp + token (per-device credentials captured once
from the app; see FINDINGS_SEEU.md). The header timestamp is NOT the wall
clock — the device only accepts the specific (ts, token) pair it knows.
"""

from __future__ import annotations

import hashlib
import io
import queue
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    import av  # PyAV — optional; without it the session runs but no JPEG is produced
    HAVE_AV = True
except ImportError:  # pragma: no cover
    HAVE_AV = False

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
MSG_HDR = 0x20          # 32 bytes per QUII message
IV = b"0" * 16          # ASCII zeros (SetIvec)
PORT = 34567
USERNAME = "adminapp2"
KEEPALIVE_SEC = 8.0
RECONNECT_SEC = 3.0
STALL_SEC = 12.0        # no decoded frames for this long → reconnect

# Per-device credentials captured once from the app (see FINDINGS_SEEU.md).
# These are constants of THIS videoporter (stable, verified repeatedly).
# `ts` is NOT wall-clock time: the device only accepts this exact value.
FIXED_TS = 0x6A71ED7F
FIXED_TOKEN = bytes.fromhex(
    "57efac413c086567725de1c1a0663feef50c6b784ad24fc17501c107"
)
# The app's clientid. A random UUID is also accepted by the device.
CLIENT_ID = "002-4112-7F950C009611492F8C4D9D73FBC56215"


# ---------------------------------------------------------------------------
# Crypto helpers (split-IV AES-CBC, IV = ASCII '0')
# ---------------------------------------------------------------------------
def _aes_crypt(data: bytes, *, key: bytes, decrypt: bool) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
    )
    fn = cipher.decryptor() if decrypt else cipher.encryptor()
    return fn.update(data) + fn.finalize()


def _encrypt_packet(clear: bytes, key: bytes) -> bytes:
    """encrypt_quii_packet: AES(hdr32) || AES(rest), each with fresh IV."""
    return _aes_crypt(clear[:MSG_HDR], key=key, decrypt=False) + _aes_crypt(
        clear[MSG_HDR:], key=key, decrypt=False
    )


def _decrypt_packet(wire: bytes, key: bytes) -> bytes:
    hdr = _aes_crypt(wire[:MSG_HDR], key=key, decrypt=True)
    if len(wire) > MSG_HDR:
        rest = _aes_crypt(wire[MSG_HDR:], key=key, decrypt=True)
        return hdr + rest
    return hdr


def _build_play(
    *,
    username: str,
    pin: str,
    client_id: str,
    ts: int,
    token: bytes,
    key: bytes,
    custom_id: bytes = b"G0112",
) -> bytes:
    """Build the 208-byte Play packet (split-IV encrypted wire)."""
    pwd = hashlib.sha256(pin.encode("utf-8")).hexdigest()
    body = (
        f"{username}&&{pwd}\x00".encode()
        + custom_id
        + b"\x00"
        + f"clientid={client_id}\x00".encode()
    )
    body_len = len(body)
    padded = 176  # pad_ext_data_len(133 + 32 sha) — matches the captured packet

    hdr = bytearray(MSG_HDR)
    hdr[0] = 0x01
    struct.pack_into("<Q", hdr, 1, ts & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<H", hdr, 9, padded & 0xFFFF)       # param_len
    struct.pack_into("<H", hdr, 0x0B, body_len & 0xFFFF)  # body_len = 133
    struct.pack_into("<H", hdr, 0x0D, 1)                  # idc
    hdr[0x0F] = 1                                         # play_arg
    hdr[0x10] = 1                                         # ids

    # Token region: after the body the device expects \x1b!< + 32-byte token,
    # zero-padded to 176. (Not the SHA256 the standard QUII play uses.)
    rest = (body + b"\x1b!<" + token)[:padded].ljust(padded, b"\x00")
    return _encrypt_packet(bytes(hdr) + rest, key)


def _build_keepalive(*, key: bytes, ts: int) -> bytes:
    """KeepAlive opcode 0x00, empty body. Uses the fixed device ts."""
    hdr = bytearray(MSG_HDR + 32)
    hdr[0] = 0x00
    struct.pack_into("<Q", hdr, 1, ts & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<H", hdr, 9, 32)  # padded SHA region
    digest = hashlib.sha256(bytes(hdr[:MSG_HDR])).digest()
    hdr[MSG_HDR:MSG_HDR + 32] = digest
    return _encrypt_packet(bytes(hdr), key)


# ---------------------------------------------------------------------------
# Media parsing
# ---------------------------------------------------------------------------
def _media_body_len(hdr: bytes) -> int:
    u32 = struct.unpack_from("<I", hdr, 0x0B)[0]
    if 0 < u32 <= 2_000_000:
        return u32
    return struct.unpack_from("<H", hdr, 0x0B)[0]


def _unpack_media_payload(hdr: bytes, body_ct: bytes, key: bytes) -> bytes:
    """Mirror PackFrame decrypt on the media body."""
    param9 = struct.unpack_from("<H", hdr, 9)[0]
    media_flag = hdr[0x0F]
    off10 = struct.unpack_from("<H", hdr, 0x10)[0]

    body = body_ct
    if param9 >= 1 and len(body) >= param9 and param9 % 16 == 0:
        body = _aes_crypt(body[:param9], key=key, decrypt=True) + body[param9:]

    if media_flag != 0:
        start = min(off10, len(body))
        media_ct = body[start:]
        aligned = len(media_ct) - (len(media_ct) % 16)
        if aligned > 0:
            pt = _aes_crypt(media_ct[:aligned], key=key, decrypt=True)
            body = body[:start] + pt + media_ct[aligned:]

    if off10 and off10 < len(body):
        return body[off10:]
    return body


def _strip_to_annexb(payload: bytes) -> bytes | None:
    """Return H.264 annex-B data (from SPS/IDR, else any video NAL)."""
    for needle in (
        b"\x00\x00\x00\x01\x67", b"\x00\x00\x00\x01\x27",
        b"\x00\x00\x01\x67", b"\x00\x00\x01\x27",
        b"\x00\x00\x00\x01\x65", b"\x00\x00\x00\x01\x25",
        b"\x00\x00\x01\x65", b"\x00\x00\x01\x25",
    ):
        i = payload.find(needle)
        if i >= 0:
            return payload[i:]
    for sc in (b"\x00\x00\x00\x01", b"\x00\x00\x01"):
        i = payload.find(sc)
        if i < 0:
            continue
        nal0 = payload[i + len(sc)] if i + len(sc) < len(payload) else 0
        if (nal0 & 0x1F) in (1, 5, 6, 7, 8, 9):
            return payload[i:]
    return None


# ---------------------------------------------------------------------------
# Persistent session
# ---------------------------------------------------------------------------
class SeeuStreamSession:
    """Long-lived QUII stream: connect → play once → decode continuously."""

    def __init__(
        self,
        ip: str,
        pin: str,
        stream_key: str,
        *,
        port: int = PORT,
        username: str = USERNAME,
        client_id: str = CLIENT_ID,
        ts: int = FIXED_TS,
        token: bytes = FIXED_TOKEN,
    ) -> None:
        self.ip = ip
        self.port = port
        self.pin = pin
        self.username = username
        self.client_id = client_id
        self.ts = ts
        self.token = token
        self.key = stream_key.encode("utf-8")[:32]

        self._lock = threading.Lock()
        self._latest_jpeg: bytes | None = None
        self._frames = 0
        self._ok = False
        self._connecting = False
        self._error = ""
        self._last_frame_at = 0.0
        self._stop = threading.Event()
        self._subscribers: list[queue.Queue[bytes | None]] = []
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._codec = None
        if HAVE_AV:
            self._codec = av.CodecContext.create("h264", "r")

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="seeu-stream", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    # -- state ---------------------------------------------------------------
    @property
    def latest_frame(self) -> bytes | None:
        with self._lock:
            return self._latest_jpeg

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._ok and not self._stop.is_set()

    @property
    def frame_count(self) -> int:
        with self._lock:
            return self._frames

    def status(self) -> dict:
        with self._lock:
            age = time.time() - self._last_frame_at if self._last_frame_at else None
            return {
                "ok": self._ok,
                "connecting": self._connecting,
                "frames": self._frames,
                "error": self._error,
                "frame_age_sec": None if age is None else round(age, 1),
            }

    # -- subscription ---------------------------------------------------------
    def subscribe(self) -> queue.Queue[bytes | None]:
        q: queue.Queue[bytes | None] = queue.Queue(maxsize=2)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[bytes | None]) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish(self, jpeg: bytes) -> None:
        with self._lock:
            self._latest_jpeg = jpeg
            self._frames += 1
            self._last_frame_at = time.time()
            self._ok = True
            self._connecting = False
            self._error = ""
            subs = list(self._subscribers)
        for q in subs:
            try:
                if q.full():
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        pass
                q.put_nowait(jpeg)
            except queue.Full:
                pass

    # -- main loop -------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._session()
            except Exception as e:  # noqa: BLE001 — session-level recovery
                if self._stop.is_set():
                    break
                with self._lock:
                    self._ok = False
                    self._connecting = False
                    self._error = f"{type(e).__name__}: {e}"
                print(f"[seeu-stream] session error: {e}", flush=True)
            if self._stop.is_set():
                break
            time.sleep(RECONNECT_SEC)

    def _session(self) -> None:
        with self._lock:
            self._connecting = True
            self._ok = False
            self._error = ""

        print(f"[seeu-stream] connect {self.ip}:{self.port}", flush=True)
        sock = socket.create_connection((self.ip, self.port), 5)
        sock.settimeout(1.0)
        self._sock = sock
        try:
            # Setup
            sock.sendall(bytes([0xA9]) + b"\x00" * (MSG_HDR - 1))
            setup_rx = self._recv_exact(sock, MSG_HDR, 4.0)
            if len(setup_rx) < MSG_HDR or setup_rx[0] != 0xA9:
                raise RuntimeError(f"setup failed: {setup_rx.hex()}")
            enc_mode = setup_rx[0x0A]
            if enc_mode not in (1, 2):
                raise RuntimeError(f"unexpected enc_mode {enc_mode}")
            print(f"[seeu-stream] setup ok enc_mode={enc_mode}", flush=True)

            # Play (dynamic login)
            play = _build_play(
                username=self.username,
                pin=self.pin,
                client_id=self.client_id,
                ts=self.ts,
                token=self.token,
                key=self.key,
            )
            sock.sendall(play)
            print(f"[seeu-stream] play sent ({len(play)}B)", flush=True)

            # Fresh codec for this session
            codec = av.CodecContext.create("h264", "r") if HAVE_AV else None

            pending = bytearray()
            last_ka = time.time()
            published0 = self._frames

            while not self._stop.is_set():
                now = time.time()
                # Stall watchdog (only after we already decoded at least one)
                with self._lock:
                    last_frame = self._last_frame_at
                    cur_frames = self._frames
                if cur_frames > published0 and last_frame and (now - last_frame) > STALL_SEC:
                    raise RuntimeError(
                        f"no decoded frames for {STALL_SEC:.0f}s — reconnecting"
                    )

                if now - last_ka >= KEEPALIVE_SEC:
                    try:
                        sock.sendall(_build_keepalive(key=self.key, ts=self.ts))
                        last_ka = now
                    except OSError as e:
                        raise RuntimeError(f"keepalive failed: {e}") from e

                try:
                    chunk = sock.recv(16384)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RuntimeError("device closed connection")
                pending.extend(chunk)

                while len(pending) >= MSG_HDR:
                    hdr = _aes_crypt(pending[:MSG_HDR], key=self.key, decrypt=True)
                    cmd = hdr[0]
                    if 0xA0 <= cmd <= 0xA3:
                        body_len = _media_body_len(hdr)
                        total = MSG_HDR + body_len
                        if len(pending) < total:
                            break
                        body_ct = bytes(pending[MSG_HDR:total])
                        del pending[:total]
                        payload = _unpack_media_payload(hdr, body_ct, self.key)
                        annex = _strip_to_annexb(payload)
                        if annex and codec:
                            for frame in codec.decode(av.Packet(bytes(annex))):
                                jpeg = self._frame_to_jpeg(frame)
                                if jpeg:
                                    self._publish(jpeg)
                        elif annex and not codec:
                            # No PyAV: still count activity so the watchdog
                            # doesn't think we're dead.
                            with self._lock:
                                self._ok = True
                                self._connecting = False
                                self._error = "PyAV not installed — no JPEG"
                    else:
                        param_len = struct.unpack_from("<H", hdr, 9)[0]
                        total = MSG_HDR + param_len
                        if len(pending) < total:
                            break
                        del pending[:total]
        finally:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _frame_to_jpeg(frame) -> bytes | None:
        try:
            img = frame.to_image()
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            return buf.getvalue()
        except Exception:
            return None

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
        sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)


# ---------------------------------------------------------------------------
# Self-test / CLI
# ---------------------------------------------------------------------------
def main() -> None:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Fermax See-U persistent live stream")
    ap.add_argument("ip", help="videoporter IP")
    ap.add_argument("--pin", default="1993")
    ap.add_argument("--key", default="2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va")
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--out", default="", help="save first JPEG here")
    args = ap.parse_args()

    if not HAVE_AV:
        print("ERROR: PyAV (av) is required", file=sys.stderr)
        return 1

    sess = SeeuStreamSession(args.ip, args.pin, args.key)
    sess.start()
    print(f"streaming {args.ip} …", flush=True)
    try:
        t0 = time.time()
        deadline = t0 + args.seconds
        last = 0
        while time.time() < deadline:
            time.sleep(0.2)
            frames = sess.frame_count
            if frames != last:
                print(f"  frames={frames} ({frames / (time.time() - t0):.1f}fps)", flush=True)
                last = frames
            if frames and args.out and not sess.latest_frame:
                pass
        jpeg = sess.latest_frame
        if jpeg:
            if args.out:
                open(args.out, "wb").write(jpeg)
                print(f"✅ saved {args.out} ({len(jpeg)}B)")
            else:
                print(f"✅ latest JPEG {len(jpeg)}B, total {sess.frame_count} frames")
            return 0
        print("❌ no frames decoded; status:", sess.status())
        return 1
    finally:
        sess.stop()


if __name__ == "__main__":
    raise SystemExit(main())
