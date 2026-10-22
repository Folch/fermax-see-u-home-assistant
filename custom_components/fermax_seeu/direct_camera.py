"""Fermax See-U camera: capture a JPEG frame from the videoporter.

Captures frames via the QUII media protocol (port 34567). Provides both a
one-shot `capture_frame()` (open + play + grab a keyframe) and a persistent
`SeeuDirectStream` session that keeps ONE connection open and decodes H.264
→ JPEG continuously (~20 fps), the way the vendor app does.

All device credentials are passed in as parameters — nothing is hardcoded
except the per-device (ts, token) constants discovered from a one-time
capture of the app (see FINDINGS_SEEU.md). The device verifies both the
password (SHA256 of the PIN) and the exact (timestamp, token) pair.

Requires: cryptography, av (PyAV), pillow.
"""

from __future__ import annotations

import hashlib
import io
import logging
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

IV = b"0" * 16  # ASCII zeros (QUII protocol)
MSG_HDR = 0x20  # 32 bytes

# Per-device stream credentials captured once from the app. `ts` is NOT the
# wall clock — the device only accepts this exact value in the play header.
FIXED_TS = 0x6A71ED7F
FIXED_TOKEN = bytes.fromhex(
    "57efac413c086567725de1c1a0663feef50c6b784ad24fc17501c107"
)
KEEPALIVE_SEC = 8.0
RECONNECT_SEC = 3.0
STALL_SEC = 12.0


@dataclass(frozen=True)
class CameraConfig:
    """Device credentials for the QUII media session."""

    ip: str
    port: int = 34567
    username: str = "adminapp2"
    pin: str = ""             # device PIN (password = SHA256(pin))
    auth_code: str = ""       # QR field "c" (plaintext, legacy)
    stream_key: str = ""      # CGI get.device.streamkey <key>
    client_id: str = ""       # e.g. "002-4112-..."
    ts: int = FIXED_TS
    token: bytes = FIXED_TOKEN
    login_hex: str = ""       # Optional captured login (replay fallback)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    d = cipher.decryptor()
    return d.update(data) + d.finalize()


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    e = cipher.encryptor()
    return e.update(data) + e.finalize()


def _recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _media_body_len(hdr: bytes) -> int:
    if len(hdr) < 0x0F:
        return 0
    u32 = struct.unpack_from("<I", hdr, 0x0B)[0]
    u16 = struct.unpack_from("<H", hdr, 0x0B)[0]
    if 0 < u32 <= 2_000_000:
        return u32
    if 0 < u16 <= 0xFFFF:
        return u16
    return struct.unpack_from("<H", hdr, 9)[0]


def _unpack_media_payload(clear_hdr: bytes, body_ct: bytes, key: bytes) -> bytes:
    """Decrypt the media payload like PackFrame does."""
    param9 = struct.unpack_from("<H", clear_hdr, 9)[0]
    media_flag = clear_hdr[0x0F]
    off10 = struct.unpack_from("<H", clear_hdr, 0x10)[0]

    body = body_ct
    if param9 >= 1 and len(body) >= param9 and param9 % 16 == 0:
        head = aes_decrypt(body[:param9], key)
        body = head + body[param9:]

    if media_flag != 0:
        start = min(off10, len(body))
        media_ct = body[start:]
        aligned = len(media_ct) - (len(media_ct) % 16)
        if aligned > 0:
            pt = aes_decrypt(media_ct[:aligned], key)
            body = body[:start] + pt + media_ct[aligned:]

    if off10 and off10 < len(body):
        return body[off10:]
    return body


def _find_keyframe(payload: bytes) -> bytes | None:
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
    for sc in (b"\x00\x00\x00\x01", b"\x00\x00\x01"):
        i = payload.find(sc)
        if i >= 0:
            return payload[i:]
    return None


def _h264_to_jpeg(h264_data: bytes) -> bytes | None:
    """Decode H.264 to JPEG using PyAV (ffmpeg fallback if av is missing)."""
    try:
        import av
    except ImportError:
        return _h264_to_jpeg_ffmpeg(h264_data)
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


def _h264_to_jpeg_ffmpeg(h264_data: bytes) -> bytes | None:
    """Decode one self-contained H.264 chunk to JPEG via ffmpeg."""
    import shutil
    import subprocess

    ffmpeg = shutil.which("ffmpeg") or "/usr/bin/ffmpeg"
    try:
        proc = subprocess.run(
            [
                ffmpeg,
                "-hide_banner", "-loglevel", "error",
                "-f", "h264", "-i", "pipe:0",
                "-frames:v", "1", "-f", "mjpeg", "pipe:1",
            ],
            input=h264_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        return None
    out = proc.stdout
    start = out.find(b"\xff\xd8\xff")
    if start < 0:
        return None
    end = out.find(b"\xff\xd9", start + 3)
    if end < 0:
        return out[start:]
    return out[start : end + 2]


def _build_play(cfg: CameraConfig) -> bytes:
    """Build the Play packet (208 bytes) with the device credentials.

    Clear layout (split-IV AES, IV = ASCII '0'):
      [32B header: opcode 0x01 | LE u64 ts | param_len | body_len | idc | ...]
      username&&SHA256(pin)\\0  G0112\\0  clientid=...\\0  \\x1b!< [32B token]
    The ts and token are per-device constants (see module docstring).
    """
    if cfg.login_hex:
        # Replay a previously-captured login (works persistently)
        return bytes.fromhex(cfg.login_hex)

    pwd = _sha256_hex(cfg.pin or cfg.auth_code)
    body = cfg.username.encode() + b"&&" + pwd.encode() + b"\x00"
    body += b"G0112\x00"  # OEM id (custom_id)
    if cfg.client_id:
        body += f"clientid={cfg.client_id}\x00".encode()
    body_len = len(body)

    # Padded (body + 32B SHA region) to a multiple of 16.
    padded = ((body_len + 32 + 15) // 16) * 16

    hdr = bytearray(MSG_HDR)
    hdr[0] = 0x01
    struct.pack_into("<Q", hdr, 1, cfg.ts & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<H", hdr, 9, padded & 0xFFFF)        # param_len
    struct.pack_into("<H", hdr, 0x0B, body_len & 0xFFFF)   # body_len
    struct.pack_into("<H", hdr, 0x0D, 1)                   # idc
    hdr[0x0F] = 1                                          # play_arg
    hdr[0x10] = 1                                          # ids

    # Token region: the device expects \\x1b!< + 32-byte token (not a SHA).
    rest = (body + b"\x1b!<" + cfg.token)[:padded].ljust(padded, b"\x00")

    key_bytes = cfg.stream_key.encode()[:32] if cfg.stream_key else (b"0" * 32)
    clear = bytes(hdr) + rest
    return aes_encrypt(clear[:MSG_HDR], key_bytes) + aes_encrypt(
        clear[MSG_HDR:], key_bytes
    )


def capture_frame(
    cfg: CameraConfig,
    duration: float = 8.0,
) -> bytes | None:
    """Connect, play, capture media, return a JPEG frame (or None)."""
    if not cfg.stream_key and not cfg.login_hex:
        raise ValueError("direct_camera: stream_key or login_hex required")

    key = cfg.stream_key.encode()[:32] if cfg.stream_key else (b"0" * 32)

    s = socket.create_connection((cfg.ip, cfg.port), 5)
    s.settimeout(2.0)
    try:
        # Setup
        setup = bytearray(MSG_HDR)
        setup[0] = 0xA9
        s.sendall(bytes(setup))
        setup_rx = _recv_exact(s, MSG_HDR, 4.0)
        if len(setup_rx) < MSG_HDR or setup_rx[0] != 0xA9:
            return None
        enc_mode = setup_rx[0x0A]

        # Play
        play = _build_play(cfg)
        s.sendall(play)

        # Capture media, parsing incrementally so we return as soon as a
        # decodable keyframe arrives (fast snapshot; doesn't hold the
        # videoporter's single connection for the whole duration).
        data = bytearray()
        pos = 0
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

            # Parse complete messages and look for a keyframe
            while pos + MSG_HDR <= len(data):
                wire_hdr = data[pos : pos + MSG_HDR]
                hdr = aes_decrypt(wire_hdr, key)
                cmd = hdr[0]
                if 0xA0 <= cmd <= 0xA3:
                    body_len = _media_body_len(hdr)
                    total = MSG_HDR + body_len
                    if pos + total > len(data):
                        break
                    body_ct = data[pos + MSG_HDR : pos + total]
                    payload = _unpack_media_payload(hdr, body_ct, key)
                    h264 = _find_keyframe(payload)
                    if h264 and len(h264) > 32:
                        jpeg = _h264_to_jpeg(h264)
                        if jpeg:
                            return jpeg
                    pos += total
                else:
                    param_len = struct.unpack_from("<H", hdr, 9)[0]
                    total = MSG_HDR + param_len
                    if pos + total > len(data):
                        break
                    pos += total

            # Compact consumed bytes so the buffer doesn't grow unbounded
            if pos > 65_536:
                del data[:pos]
                pos = 0

        return None
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Persistent live-stream session (fluid live video, like the vendor app)
# ---------------------------------------------------------------------------
class _FfmpegMjpegDecoder:
    """Incremental H.264 → MJPEG decoder via ffmpeg (fallback when PyAV missing).

    HA bundles an ffmpeg binary, so this keeps the integration self-contained
    even if the `av` wheel cannot be installed. Mirrors the proven approach of
    the quii-lan-client viewer: pipe annex-B H.264 in, split JPEGs out.
    """

    def __init__(self, on_jpeg) -> None:
        import shutil
        import subprocess

        self._ffmpeg = shutil.which("ffmpeg") or "/usr/bin/ffmpeg"
        self._on_jpeg = on_jpeg
        self._proc = subprocess.Popen(
            [
                self._ffmpeg,
                "-hide_banner", "-loglevel", "error",
                "-fflags", "nobuffer",
                "-flags", "low_delay",
                "-probesize", "32768",
                "-analyzeduration", "0",
                "-f", "h264",
                "-i", "pipe:0",
                "-an",
                "-f", "mjpeg",
                "-q:v", "6",
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self._buffer = bytearray()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self) -> None:
        """Read ffmpeg stdout, split on JPEG SOI/EOI, push to the callback."""
        while self._proc.poll() is None:
            try:
                chunk = self._proc.stdout.read(4096)
            except Exception:
                break
            if not chunk:
                break
            self._buffer.extend(chunk)
            while True:
                start = self._buffer.find(b"\xff\xd8\xff")
                if start < 0:
                    break
                if start > 0:
                    del self._buffer[:start]
                end = self._buffer.find(b"\xff\xd9", 3)
                if end < 0:
                    break
                jpg = bytes(self._buffer[: end + 2])
                del self._buffer[: end + 2]
                try:
                    self._on_jpeg(jpg)
                except Exception:
                    pass

    def decode(self, annex: bytes) -> None:
        if annex and self._proc.poll() is None:
            try:
                self._proc.stdin.write(annex)
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.kill()
        except Exception:
            pass


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


def _build_keepalive(*, key: bytes, ts: int) -> bytes:
    """KeepAlive opcode 0x00, empty body, fixed device ts."""
    hdr = bytearray(MSG_HDR + 32)
    hdr[0] = 0x00
    struct.pack_into("<Q", hdr, 1, ts & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<H", hdr, 9, 32)
    digest = hashlib.sha256(bytes(hdr[:MSG_HDR])).digest()
    hdr[MSG_HDR:MSG_HDR + 32] = digest
    clear = bytes(hdr)
    return aes_encrypt(clear[:MSG_HDR], key) + aes_encrypt(
        clear[MSG_HDR:], key
    )


class SeeuDirectStream:
    """Long-lived QUII stream: connect → play once → decode continuously.

    Mirrors the `latest_frame` / `is_active` interface of the cloud
    `FermaxStreamSession` so the camera entity can treat both the same way.
    """

    def __init__(self, cfg: CameraConfig) -> None:
        self.cfg = cfg
        self.key = cfg.stream_key.encode()[:32] if cfg.stream_key else (b"0" * 32)
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
        # Optional callback invoked (from the stream thread) the first time a
        # frame is decoded — lets the integration flip the camera to
        # "Streaming" exactly when live frames start flowing.
        self.on_first_frame = None

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="seeu-direct-stream", daemon=True
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

    # -- subscription --------------------------------------------------------
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
            first = self._frames == 0
            self._latest_jpeg = jpeg
            self._frames += 1
            self._last_frame_at = time.time()
            self._ok = True
            self._connecting = False
            self._error = ""
            subs = list(self._subscribers)
        if first:
            _LOGGER.info(
                "Direct camera: first frame decoded from %s (%d B)",
                self.cfg.ip,
                len(jpeg),
            )
            cb = self.on_first_frame
            if cb:
                try:
                    cb()
                except Exception:
                    pass
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

    # -- main loop -----------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._session()
            except Exception as err:  # noqa: BLE001 — session recovery
                if self._stop.is_set():
                    break
                with self._lock:
                    self._ok = False
                    self._connecting = False
                    self._error = f"{type(err).__name__}: {err}"
            if self._stop.is_set():
                break
            time.sleep(RECONNECT_SEC)

    def _session(self) -> None:
        with self._lock:
            self._connecting = True
            self._ok = False
            self._error = ""

        sock = socket.create_connection((self.cfg.ip, self.cfg.port), 5)
        sock.settimeout(1.0)
        self._sock = sock
        try:
            # Setup
            sock.sendall(bytes([0xA9]) + b"\x00" * (MSG_HDR - 1))
            setup_rx = _recv_exact(sock, MSG_HDR, 4.0)
            if len(setup_rx) < MSG_HDR or setup_rx[0] != 0xA9:
                raise RuntimeError(f"setup failed: {setup_rx.hex()}")
            if setup_rx[0x0A] not in (1, 2):
                raise RuntimeError(f"unexpected enc_mode {setup_rx[0x0A]}")

            # Play (dynamic login)
            sock.sendall(_build_play(self.cfg))

            # Fresh codec for this session: PyAV preferred, ffmpeg fallback
            # (HA bundles ffmpeg) so the integration is self-contained.
            codec = None
            ffmpeg_decoder = None
            try:
                import av

                codec = av.CodecContext.create("h264", "r")
            except ImportError:
                try:
                    ffmpeg_decoder = _FfmpegMjpegDecoder(self._publish)
                    _LOGGER.warning(
                        "PyAV not installed — using ffmpeg fallback to decode "
                        "the direct camera stream (%s)",
                        self.cfg.ip,
                    )
                except Exception as err:  # noqa: BLE001
                    _LOGGER.error(
                        "No video decoder available (PyAV missing and ffmpeg "
                        "failed: %s). Install av>=13.0.0 and restart HA.",
                        err,
                    )

            pending = bytearray()
            last_ka = time.time()
            published0 = self._frames

            while not self._stop.is_set():
                now = time.time()
                with self._lock:
                    last_frame = self._last_frame_at
                    cur_frames = self._frames
                if (
                    cur_frames > published0
                    and last_frame
                    and (now - last_frame) > STALL_SEC
                ):
                    raise RuntimeError(
                        f"no decoded frames for {STALL_SEC:.0f}s — reconnecting"
                    )

                if now - last_ka >= KEEPALIVE_SEC:
                    try:
                        sock.sendall(_build_keepalive(key=self.key, ts=self.cfg.ts))
                        last_ka = now
                    except OSError as err:
                        raise RuntimeError(f"keepalive failed: {err}") from err

                try:
                    chunk = sock.recv(16384)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RuntimeError("device closed connection")
                pending.extend(chunk)

                while len(pending) >= MSG_HDR:
                    hdr = aes_decrypt(pending[:MSG_HDR], self.key)
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
                                jpeg = _frame_to_jpeg(frame)
                                if jpeg:
                                    self._publish(jpeg)
                        elif annex and ffmpeg_decoder:
                            ffmpeg_decoder.decode(annex)
                        elif annex:
                            # No decoder available — do NOT mark the stream
                            # active (that would report "Streaming" with no
                            # frames). Fall through so the camera serves
                            # snapshots instead of claiming a live stream.
                            with self._lock:
                                if not self._error:
                                    self._error = "no video decoder available"
                    else:
                        param_len = struct.unpack_from("<H", hdr, 9)[0]
                        total = MSG_HDR + param_len
                        if len(pending) < total:
                            break
                        del pending[:total]
        finally:
            self._sock = None
            if ffmpeg_decoder is not None:
                ffmpeg_decoder.close()
            try:
                sock.close()
            except OSError:
                pass


def _frame_to_jpeg(frame) -> bytes | None:
    try:
        img = frame.to_image()
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        return buf.getvalue()
    except Exception:
        return None
