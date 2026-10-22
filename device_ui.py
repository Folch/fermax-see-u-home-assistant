#!/usr/bin/env python3
"""Fermax See-U Device Test UI.

Serveix una pàgina web per provar les comandes CGI del videoporter
directament per la xarxa local, sense necessitat del cloud de Fermax.

Ús:
    python3 device_ui.py
    Obre http://localhost:8080
"""

import hashlib
import json
import os
import queue
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

# Allow importing seeu_camera.py from this repo
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ==== CONFIGURACIÓ ====
# Cambia això si la IP del dispositiu o el PIN canvien
DEVICE_HOST = "192.168.1.145"
DEVICE_URL = f"https://{DEVICE_HOST}/tdkcgi"
DEVICE_USERNAME = "adminapp2"
DEVICE_PIN = "1993"
# get.device.streamkey → <key> (clau AES del stream QUII)
STREAM_KEY = "2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va"

# Sessió de live persistent (seeu_stream.py). Es crea al primer
# /api/live/start i s'allibera a /api/live/stop.
try:
    from seeu_stream import SeeuStreamSession
    HAVE_STREAM = True
except Exception:
    HAVE_STREAM = False

_live_session = None
_live_lock = threading.Lock()

def device_password(pin: str = DEVICE_PIN) -> str:
    """SHA256 hash of the device PIN."""
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()

PASSWORD_HASH = device_password()


def build_xml(command: str, content_xml: str = "") -> str:
    """Build a device CGI XML request."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<envelope>
  <header>
    <security>username</security>
    <username>{DEVICE_USERNAME}</username>
    <password>{PASSWORD_HASH}</password>
    <passwordencode>1</passwordencode>
  </header>
  <body>
    <command>{command}</command>
    <content>{content_xml}</content>
  </body>
</envelope>"""


async def send_command(command: str, content_xml: str = "") -> dict:
    """Send a CGI command to the device and return the result."""
    xml = build_xml(command, content_xml)
    headers = {
        "Content-Type": "application/xml",
        "charset": "utf-8",
        "Accept": "application/xml",
        "User-Agent": "SeeU/1.0.4.6 (com.fermax.seeu; iOS 14.0)",
    }
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        try:
            resp = await client.post(DEVICE_URL, headers=headers, content=xml)
            return {
                "ok": resp.status_code == 200,
                "status": resp.status_code,
                "body": resp.text[:4000],
                "error": None,
            }
        except Exception as e:
            return {"ok": False, "status": 0, "body": "", "error": str(e)}


PAGE = """<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fermax See-U — Test del dispositiu</title>
<style>
:root { color-scheme: dark; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #111; color: #eee; }
h1 { font-size: 1.4em; margin: 0; }
.sub { color: #888; font-size: .85em; margin: 4px 0 16px; }
.container { max-width: 760px; margin: 0 auto; padding: 20px; }
.card { background: #1c1c1e; border: 1px solid #333; border-radius: 10px; padding: 16px; margin-bottom: 14px; }
.card h2 { font-size: 1em; margin: 0 0 10px; color: #4cc2ff; }
.row { display: flex; gap: 8px; flex-wrap: wrap; }
button { background: #2c2c2e; color: #eee; border: 1px solid #444; border-radius: 6px; padding: 8px 14px; cursor: pointer; font-size: .9em; }
button:hover { background: #3a3a3c; }
button.primary { background: #0a84ff; border-color: #0a84ff; }
button.primary:hover { background: #3395ff; }
button.danger { background: #ff453a; border-color: #ff453a; }
input, select { background: #2c2c2e; color: #eee; border: 1px solid #444; border-radius: 6px; padding: 8px; font-size: .9em; }
input[type=text] { width: 220px; }
pre { background: #000; border: 1px solid #333; border-radius: 6px; padding: 12px; overflow: auto; max-height: 400px; font-size: .78em; white-space: pre-wrap; word-break: break-all; }
#result { margin-top: 12px; }
#result .ok { color: #30d158; }
#result .err { color: #ff453a; }
label { display: block; margin: 6px 0 2px; font-size: .85em; color: #aaa; }
.section-note { font-size: .8em; color: #888; margin-top: 6px; }
.config { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
</style>
</head>
<body>
<div class="container">
<h1>🔔 Fermax See-U — Test del dispositiu</h1>
<div class="sub">Connexió directa al videoporter per la xarxa local (CGI). Sense cloud.</div>

<div class="card">
<h2>⚙️ Configuració</h2>
<div class="config">
<div><label>IP del dispositiu</label><input type="text" id="device_ip" value="192.168.1.145"></div>
<div><label>PIN</label><input type="text" id="device_pin" value="1993"></div>
</div>
<div class="row" style="margin-top:10px"><button onclick="saveConfig()">💾 Desar configuració</button></div>
<div class="section-note">El password s'envia com a SHA256 del PIN. Usuari: <code>adminapp2</code></div>
</div>

<div class="card">
<h2>🔓 Obrir porta</h2>
<div class="row">
<button class="primary" onclick="openDoor()">🚪 Obrir porta (PIN 1993)</button>
<button onclick="openDoorEmpty()">🚪 Obrir porta (password buit)</button>
<button onclick="openDoorCheck()">🔑 Check password primer</button>
</div>
<div><label>Password d'obertura (opcional, es xifra amb SHA256)</label><input type="text" id="unlock_pwd" placeholder="deixa buit per provar sense password"></div>
<div class="section-note">Resultat: amb PIN → <code>error 0</code> (accepta però no obre). Amb buit → <code>error -3</code> (password requerit). Pot necessitar un password d'obertura separat del PIN.</div>
</div>

<div class="card">
<h2>🔧 Accions</h2>
<div class="row">
<button onclick="send('get.device.status', '')">📊 Estat</button>
<button onclick="send('get.product.info', '')">ℹ️ Info producte</button>
<button onclick="send('get.device.streamkey', '')">🔑 Stream key</button>
<button onclick="send('get.device.qrcode', '')">🔳 QR code</button>
<button onclick="send('get.live.status', '')">📡 Live status</button>
<button onclick="send('get.system.status', '')">🖥️ Sistema</button>
<button onclick="send('get.record.session', '')">📼 Record session</button>
<button onclick="send('get.ptz.preset', '')">🎥 PTZ preset</button>
</div>
<div class="section-note">✅ <code>get.device.status</code> i <code>get.device.streamkey</code> verificats. La càmera va per protocol QV natiu (port 34567) — pendent d'implementar.</div>
</div>

<div class="card">
<h2>✍️ Comanda personalitzada</h2>
<div><label>Comanda XML</label><input type="text" id="custom_command" value="get.device.status"></div>
<div><label>Contingut XML (opcional)</label><textarea id="custom_content" rows="3" style="width:100%;background:#2c2c2e;color:#eee;border:1px solid #444;border-radius:6px;padding:8px;font-family:monospace"></textarea></div>
<div class="row" style="margin-top:8px"><button onclick="send(document.getElementById('custom_command').value, document.getElementById('custom_content').value)">▶️ Enviar</button></div>
</div>

<div class="card">
<h2>📹 Càmera</h2>
<div class="row">
<button class="primary" onclick="captureCamera()">📸 Capturar frame</button>
<button id="btnLive" onclick="toggleLive()">🔴 Live (loop)</button>
</div>
<div class="section-note">El live obre <b>una sola connexió</b> i hi rep frames de manera continuada (MJPEG) — fluït com l'app, sense saltar cada 5s.</div>
<div id="camera_result">
  <img id="live_img" style="display:none;max-width:100%;border-radius:8px;border:1px solid #444">
  <div id="camera_note" class="section-note">— cap imatge encara —</div>
</div>
</div>

<div id="result"></div>
</div>

<script>
let device_ip = '192.168.1.145';
let device_pin = '1993';

function saveConfig() {
  device_ip = document.getElementById('device_ip').value;
  device_pin = document.getElementById('device_pin').value;
  const el = document.getElementById('result');
  el.innerHTML = '<div class="ok">✅ Configuració desada: ' + device_ip + ' / PIN ' + device_pin + '</div>';
}

function openLockXml(pwdHash) {
  return '<door>1</door><locknumber>1</locknumber><password>' + (pwdHash || '') + '</password>';
}

function openDoor() {
  const pwd = sha256(device_pin);
  send('set.device.opendoor', openLockXml(pwd));
}

function openDoorEmpty() {
  send('set.device.opendoor', openLockXml(''));
}

function openDoorCheck() {
  const pwd = sha256(device_pin);
  send('set.opendoor.checkpassword', '<password>' + pwd + '</password>');
}

async function send(command, contentXml) {
  const resultEl = document.getElementById('result');
  resultEl.innerHTML = '<div>⏳ Enviant <code>' + command + '</code>...</div>';
  try {
    const resp = await fetch('/api/command', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        command: command,
        content: contentXml || '',
        ip: device_ip,
        pin: device_pin
      })
    });
    const data = await resp.json();
    if (data.ok) {
      resultEl.innerHTML = '<div class="ok">✅ ' + command + ' → HTTP ' + data.status + '</div><pre>' + esc(data.body) + '</pre>';
    } else {
      resultEl.innerHTML = '<div class="err">❌ ' + command + ' → HTTP ' + data.status + (data.error ? ' — ' + data.error : '') + '</div><pre>' + esc(data.body) + '</pre>';
    }
  } catch (e) {
    resultEl.innerHTML = '<div class="err">❌ Error: ' + esc(String(e)) + '</div>';
  }
}

let liveOn = false;

function cameraImg() { return document.getElementById('live_img'); }
function cameraNote() { return document.getElementById('camera_note'); }

async function captureCamera() {
  if (liveOn) return;  // don't fight the live stream
  const img = cameraImg(), note = cameraNote();
  note.textContent = '⏳ Capturant frame…';
  try {
    const resp = await fetch('/api/camera', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip: device_ip, pin: device_pin})
    });
    const data = await resp.json();
    if (data.ok && data.jpg) {
      img.src = 'data:image/jpeg;base64,' + data.jpg;
      img.style.display = 'block';
      note.textContent = '✅ Frame a les ' + new Date().toLocaleTimeString() + ' (' + data.size + 'B)';
    } else {
      note.textContent = '❌ ' + (data.error || 'sense frame');
    }
  } catch (e) {
    note.textContent = '❌ Error: ' + esc(String(e));
  }
}

async function toggleLive() {
  const btn = document.getElementById('btnLive');
  const img = cameraImg(), note = cameraNote();
  if (liveOn) {
    liveOn = false;
    btn.textContent = '🔴 Live (loop)';
    img.style.display = 'none';
    img.removeAttribute('src');
    note.textContent = 'Live aturat.';
    try { await fetch('/api/live/stop', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'}); } catch (e) {}
    return;
  }
  liveOn = true;
  btn.textContent = '⏹ Aturar live';
  note.textContent = '⏳ Connectant al videoporter…';
  try {
    const r = await fetch('/api/live/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip: device_ip, pin: device_pin})
    });
    const j = await r.json();
    if (!j.ok) {
      note.textContent = '❌ ' + (j.error || 'no es pot iniciar el live');
      liveOn = false;
      btn.textContent = '🔴 Live (loop)';
      return;
    }
    img.src = '/stream.mjpg?' + Date.now();
    img.style.display = 'block';
    img.onload = () => { note.textContent = '🔴 Stream en directe — fluït'; };
    img.onerror = () => { note.textContent = '⚠️ Stream aturat'; };
  } catch (e) {
    note.textContent = '❌ Error: ' + esc(String(e));
    liveOn = false;
    btn.textContent = '🔴 Live (loop)';
  }
}

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function sha256(str) {
  // SHA-256 en JS (net)
  function rrot(n,x,c){return(x>>>c)|(x<<(32-c));}
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  function utf8(s){return unescape(encodeURIComponent(s));}
  var str2=utf8(str), h=0, l=str2.length;
  var n=(((l+8)>>6)+1)*16, words=[]; for(var i=0;i<n;i++)words[i]=0;
  for(var j=0;j<l;j++)words[j>>2]|=(str2.charCodeAt(j)&0xff)<<(24-(j%4)*8);
  words[l>>2]|=(0x80)<<(24-((l%4)*8)); words[((l+8)>>6)*16+15]=l*8;
  for(var m=0;m<n;m+=16){
    for(var i2=0;i2<16;i2++)words[m+i2]=words[m+i2];
    for(var t=16;t<64;t++){var a=words[m+t-15],b=words[m+t-2];
      words[m+t]=((((a>>>7)|(a<<25))^((a>>>18)|(a<<14))^(a>>>3))+words[m+t-7]+(((b>>>17)|(b<<15))^((b>>>19)|(b<<13))^(b>>>10))+words[m+t-16])|0;}
    var A=H[0],B=H[1],C=H[2],D=H[3],E=H[4],F=H[5],G=H[6],Hh=H[7];
    for(var t2=0;t2<64;t2++){var S1=rrot(0,E,6)^rrot(0,E,11)^rrot(0,E,25),ch=(E&F)^(~E&G),t1=(Hh+S1+ch+K[t2]+words[m+t2])|0;
      var S0=rrot(0,A,2)^rrot(0,A,13)^rrot(0,A,22),maj=(A&B)^(A&C)^(B&C),t2v=(S0+maj)|0;
      Hh=G;G=F;F=E;E=(D+t1)|0;D=C;C=B;B=A;A=(t1+t2v)|0;}
    H[0]=(H[0]+A)|0;H[1]=(H[1]+B)|0;H[2]=(H[2]+C)|0;H[3]=(H[3]+D)|0;H[4]=(H[4]+E)|0;H[5]=(H[5]+F)|0;H[6]=(H[6]+G)|0;H[7]=(H[7]+Hh)|0;
  }
  return H.map(function(x){return('00000000'+(x>>>0).toString(16)).slice(-8);}).join('');
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PAGE.encode("utf-8"))
        elif self.path.startswith("/stream.mjpg"):
            self._serve_mjpeg()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_mjpeg(self):
        """Serveix el stream continu (multipart/x-mixed-replace) de la sessió."""
        if not _live_session:
            self.send_response(503)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        q = _live_session.subscribe()
        try:
            latest = _live_session.latest_frame
            if latest:
                self.wfile.write(
                    b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                    + str(len(latest)).encode() + b"\r\n\r\n" + latest + b"\r\n"
                )
            while True:
                try:
                    jpg = q.get(timeout=8)
                except queue.Empty:
                    continue
                if jpg is None:
                    break
                self.wfile.write(
                    b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                    + str(len(jpg)).encode() + b"\r\n\r\n" + jpg + b"\r\n"
                )
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            _live_session.unsubscribe(q)

    def do_POST(self):
        global _live_session
        if self.path == "/api/command":
            import asyncio
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            command = body.get("command", "get.device.status")
            content = body.get("content", "")
            ip = body.get("ip", DEVICE_HOST)
            pin = body.get("pin", DEVICE_PIN)

            global DEVICE_URL
            DEVICE_URL = f"https://{ip}/tdkcgi"

            # Use the per-request pin to build the password hash
            pwd_hash = device_password(pin)
            global PASSWORD_HASH, build_xml
            PASSWORD_HASH = pwd_hash

            async def run():
                return await send_command(command, content)

            result = asyncio.run(run())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        elif self.path == "/api/live/start":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            ip = body.get("ip", DEVICE_HOST)
            pin = body.get("pin", DEVICE_PIN)

            if not HAVE_STREAM:
                result = {"ok": False, "error": "seeu_stream/PyAV no disponible"}
            else:
                with _live_lock:
                    if _live_session is not None and _live_session.is_active:
                        result = {"ok": True, "already": True}
                    else:
                        if _live_session is not None:
                            _live_session.stop()
                        sess = SeeuStreamSession(ip, pin, STREAM_KEY)
                        sess.start()
                        _live_session = sess
                        result = {"ok": True}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        elif self.path == "/api/live/stop":
            with _live_lock:
                if _live_session is not None:
                    _live_session.stop()
                    _live_session = None
            result = {"ok": True}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        elif self.path == "/api/camera":
            import asyncio
            import base64
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            ip = body.get("ip", DEVICE_HOST)
            pin = body.get("pin", DEVICE_PIN)

            try:
                from seeu_camera import capture_frame
                # capture_frame is synchronous and returns JPEG bytes
                jpeg = capture_frame(ip, duration=8.0)
                if jpeg:
                    result = {
                        "ok": True,
                        "size": len(jpeg),
                        "jpg": base64.b64encode(jpeg).decode("ascii"),
                    }
                else:
                    result = {"ok": False, "error": "no frame captured"}
            except Exception as e:
                result = {"ok": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print("[HTTP] %s" % (format % args))


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print(f"=== Fermax See-U Device Test UI ===")
    print(f"Dispositiu: {DEVICE_URL}")
    print(f"Usuari: {DEVICE_USERNAME} | PIN: {DEVICE_PIN} | SHA256: {PASSWORD_HASH}")
    print(f"Obre: http://localhost:{port}")
    print("Ctrl+C per aturar")
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAturat.")
        server.server_close()
