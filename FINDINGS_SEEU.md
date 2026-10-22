# Fermax See-U — Findings tècnics

> Data: 2026-08-04 · Repo: `fermax-blue-hass` · Dispositiu: Fermax See-U (IDS94C3W)

---

## ✅ RESUM EXECUTIU

**L'autenticació cloud de Fermax NO és necessària.** El videoporter See-U es controla **directament per la xarxa local** via CGI XML, utilitzant credencials del dispositiu (`adminapp2` + `SHA256(PIN)`). Això s'ha **verificat funcionant** (veure secció "El que funciona").

El camí cloud (`oauth-pro-duoxme.fermax.io`) existeix però requereix un compte creat al servidor durant el `dev-bind-register`, que **no es pot derivar del QR** — només l'app el coneix.

---

## 🆕 ACTUALITZACIÓ 2026-08-04 — LOGIN DINÀMIC + STREAM FLUID ✅

**El login del stream (port 34567) s'ha reconstruït completament i es construeix
dinàmicament.** El tros que faltava: el dispositiu **verifica el timestamp del
header** (no és l'hora del rellotge!) i **un token fix de 32 bytes**.

### Estructura real del paquet Play (desxifrat amb *split IV*, 208 bytes)

```
[32B header] 01 | LE-u64 ts | 00b0 | 0085 | 0001 | 01 | 01 | 00…
              ^ opcode  ^ param_len=176  ^ body_len=133  ^ idc / play / ids
adminapp2 && SHA256(PIN) \0  G0112 \0  clientid=002-4112-... \0  \x1b!< [32B token] [zeros]
```

- **Password = `adminapp2 && SHA256(PIN)`** — el SHA256 **complet** del PIN
  (ex. `8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2`
  per PIN `1993`). NO és SHA256(auth_code).
- **`G0112`** = OEM id (custom_id). **clientid** = `002-4112-{hex32}`.
- **`ts` = `0x6A71ED7F`** i **token = `57efac413c086567725de1c1a0663feef50c6b784ad24fc17501c107`**
  són **constants del dispositiu** (capturades un cop de l'app). Si es canvien
  (ts ±1s o token aleatori) → el dispositiu **rebutja** (0B / 64B NAK).
- **Encriptació**: AES-256-CBC *split* — `AES(hdr32) || AES(rest)`, IV = `'0'*16`
  en cada tros (no una cadena contínua). Clau = streamkey (`2S8ofGm0...`, estable).

El desxifrat en cadena única donava un "nonce" i un password truncat
(`24534e9f...` = SHA256[5:]) que eren **artifacts del desxifrat incorrecte**.

### ✅ STREAM FLUID (com l'app) — sessió persistent

El codi anterior obria **una connexió nova per frame** (setup+play+espera de
keyframe ≈ 5s). L'app obre **UNA connexió** i rep frames contínuament.

- **Implementació**: `seeu_stream.py` (eines CLI) i `SeeuDirectStream` a
  `direct_camera.py` (integració HA).
- Una sola connexió → setup+play un cop → parseja paquets media `0xA0-0xA3`
  contínuament → annex-B H.264 → `av.CodecContext` incremental → JPEG.
- **Rendiment verificat: ~20 fps** (352x240). Keepalive cada 8s, reconnexió
  automàtica si s'estanca (>12s sense frames) o el dispositiu tanca.
- `device_ui.py`: el live ara serveix **MJPEG** (`/stream.mjpg`) des de la
  sessió persistent — sense flicker (el `<img>` ja no es recrea cada cop).

---

## 🔑 CREDENCIALS DE CONNEXIÓ DIRECTA (FUNCIONEN ✅)

| Dada | Valor |
|------|-------|
| **URL** | `https://192.168.1.145/tdkcgi` |
| **Port** | 443 (HTTPS) |
| **Usuari** | `adminapp2` |
| **Password** | `SHA256("1993")` = `8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2` |
| **Encode** | `passwordencode=1` (indica SHA256) |
| **Security** | `username` |
| **Protocol** | POST XML via CGI |

### Detalls del dispositiu (retornats per `get.device.status`)

```xml
<mac>e8:5c:5f:a0:2b:d8</mac>
<version>V100.R001.A312.00.G0112.B011</version>
<releasedate>2024-06-04t17:27:06z</releasedate>
<model>IDS94C3W</model>
```

- **PIN de l'usuari**: `1993` (configurat a l'app, és la contrasenya del dispositiu)
- L'usuari va intentar canviar-lo a `3991` via `set.seurity.verifycode` → **"Fail to Modify"** (falla, el PIN continua sent `1993`)
- `adminapp2` = `SDKConst.DEVICE_USER_NAME` (usuari admin del dispositiu)
- La contrasenya es xifra amb **SHA256** abans d'enviar-se (mai en clar)

---

## 🏠 CONNEXIÓ DIRECTA (LAN) — VERIFICADA ✅

### Petició que funciona

```http
POST https://192.168.1.145/tdkcgi
Content-Type: application/xml
charset: utf-8
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<envelope>
  <header>
    <security>username</security>
    <username>adminapp2</username>
    <password>8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2</password>
    <passwordencode>1</passwordencode>
  </header>
  <body>
    <command>get.device.status</command>
    <content/>
  </body>
</envelope>
```

**Resposta: `200 OK`** amb l'estat complet del dispositiu (MAC, model, versió, timezone, estat vídeo, etc.)

### Comandes del dispositiu (del codi descompilat)

| Comanda | XML `<command>` | Propòsit |
|---------|----------------|----------|
| Estat | `get.device.status` | Estat complet (✅ provada) |
| **Obrir porta** | `set.device.opendoor` | Obrir el pany |
| Info | `get.product.info` | Informació del dispositiu |
| Cloud info | `get.network.cloud` | Informació de connexió cloud |
| Stream key | `get.device.streamkey` | Claus de streaming |
| QR code | `get.device.qrcode` | QR del dispositiu |
| Record session | `get.record.session` | Sessions de gravació |
| Record search | `get.record.search` | Cerca de gravacions |
| Record message | `get.record.message` | Missatges de gravació |
| PTZ preset | `get.ptz.preset` | Presets PTZ |
| Live status | `get.live.status` | Estat en directe |
| Sistema | `get.system.status` | Estat del sistema |

### Formats de contingut per obrir la porta

**`openLock(password, lockNum)`** → `set.device.opendoor`:
```xml
<content>
  <door>1</door>
  <password>{SHA256(1993)}</password>
</content>
```

**`deviceUnlock(password, channelNum, lockNum)`** → `set.device.opendoor`:
```xml
<content>
  <door>1</door>
  <locknumber>1</locknumber>
  <password>{SHA256(1993)}</password>
</content>
```

---

## ☁️ AUTENTICACIÓ CLOUD — ANÀLISI (NO FUNCIONA PER QR)

### L'endpoint OAuth que fa servir l'app

| Component | Valor |
|-----------|-------|
| Endpoint token | `oauth-pro-duoxme.fermax.io/oauth/token` |
| Client ID | `dpv7iqz6ee5mazm1iq9dw1d42slyut48kj0mp5fvo58j5ih` |
| Client Secret | `c7ylkqpujwah85yhnprv0wdvyzutlcnkw4sz90buldbulk1` |
| Auth Basic (base64) | `ZHB2N2lxejZlZTVtYXptMWlxOWR3MWQ0MnNseXV0NDhrajBtcDVmdm81OGo1aWg6Yzd5bGtxcHVqd2FoODV5aG5wcnYwd2R2eXp1dGxjbmt3NHN6OTBidWxkYnVsazE=` |

### Què s'ha provat i els resultats

| Prova | Resultat |
|-------|----------|
| Client credentials (`client_credentials` grant) | `400 unauthorized_client` — **client vàlid** però no autoritzat per aquest grant |
| Password grant amb credencials del QR (308 combinacions) | `400 invalid_grant` — **client vàlid**, username/password incorrectes |
| `GET /qvoauthv2/token` | `200 HTML "Sign in"` — és un flow de navegador, no una API |
| `POST /qvoauthv2/token` (client_id al body) | `403 Forbidden` |
| `POST /auth/nologin;jus_duplex=up` (XML dev-bind-register) | `400 Bad Request` |
| `GET /auth/nologin;jus_duplex=down` | `400 Bad Request` |
| `POST /auth/user;jus_duplex=up` | `400 Bad Request` |

### Per què no funciona el cloud amb el QR

Del codi descompilat (`QvOAuthManager.getToken()`, `QvApi2.bindDevice`):

```
1. L'app fa dev-bind-register amb el QR (device-id, auth-code)
2. El SERVIDOR assigna un account + password (UUID aleatori)
3. L'OAuth usa: usr = account_assignat, pwd = SHA256(UUID_aleatori)
```

El QR només conté **dades del dispositiu** (uid, auth code, MAC) — **no** l'account. L'account el crea el servidor quan el dispositiu es vincula, i només l'app el coneix (guardat com `noLoginUserName` / `noLoginPassword`).

### Dades del QR (dispositiu)

```json
{
  "v": 1,
  "u": "25025kt9aysi",
  "c": "VKMFNOIO",
  "m": "IDS94C3W",
  "a": "IDS94C3Waysi",
  "d": "b0211111",
  "b": "e8:5c:5f:a0:2b:d8"
}
```

| Camp | Valor | Significat |
|------|-------|-----------|
| `u` | `25025kt9aysi` | UID del dispositiu |
| `c` | `VKMFNOIO` | Auth code del dispositiu |
| `m` | `IDS94C3W` | Model |
| `a` | `IDS94C3Waysi` | AP name / identificador d'instal·lació |
| `d` | `b0211111` | Device ID |
| `b` | `e8:5c:5f:a0:2b:d8` | MAC (coincideix amb el dispositiu) |

---

## 🔍 FLUX DE L'APP (del codi descompilat)

### Versions

- **APK Android**: `com.fermax.see.u` v1.0.1(3), BuildConfig `AUTH_CODE=2`
- **App iOS**: `com.fermax.seeu` v1.0.4.6 (capturat al tràfic)

### Config de l'app (AppConfig)

| Constant | Valor |
|----------|-------|
| `SERVER_ADDRESS` | `fermax.qvcloud.net` |
| `OEM_ID` | `G0112` |
| `APP_ID` | `4112` |
| `CLIENT_TYPE` | 3 (Android) |
| `AUTH_MODE_AVAILABLE` | 1 = **no-login** |
| `ALARM_CLIENT_ID` | `003-4112-{AndroidID}` (format) |

### XML d'autenticació

- **Login**: `POST /auth/user;jus_duplex=up` (o `/auth/nologin;jus_duplex=up` en no-login)
- **Down-channel** (long-polling): `GET /auth/nologin;jus_duplex=down`
- **Header del client XML**: `Content-Type: application/xml` + `charset: utf-8`
- **Version XML**: `v1.13` (AUTH_VERSION_CODE=2)

### El protocol de dispositius (CGI)

- **Path**: `/tdkcgi`
- **Content-Type**: `application/xml`
- L'app connecta directament al videoporter (vegeu el tràfic capturat amb mitmproxy)

### Ports oberts al dispositiu (escaneig)

| Port | Estat | Ús |
|------|-------|----|
| 443 | ✅ OPEN | CGI `/tdkcgi` (control) |
| 34567 | ✅ OPEN | Streaming de vídeo (protocol QV natiu) |
| 80 | ❌ tancat | — |
| 554 | ❌ tancat | No hi ha RTSP |
| 8554 | ❌ tancat | No hi ha RTSP alternatiu |

### Streaming de vídeo

**No hi ha snapshot CGI ni RTSP.** El vídeo va pel **protocol QV natiu** (port 34567):

1. `get.device.streamkey` → retorna `key` + `tdc` (token)
2. La llibreria nativa `liblive_player.so` usa aquest token per connectar-se al port 34567
3. És un protocol propietari complex de reimplementar

`get.device.streamkey` retorna:
```xml
<key>2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va</key>
<tdc>eeccQZHXscAhwiNhHK0+zMYChvyLX/aFAElAr5FY6JxEBM8YnRFuBIc+1ft1NSMeX/...</tdc>
```

### Obrir la porta (`set.device.opendoor`)

**Accepta la comanda però la porta no obre.** Resultats provats:

| Content | Error | Resultat |
|---------|-------|----------|
| `<door>1</door><password>{SHA256(1993)}</password>` | `0` | ✅ comanda acceptada, ❌ **no obre** |
| `<door>1</door><locknumber>1</locknumber><password>{SHA256(1993)}</password>` | `0` | ✅ comanda acceptada, ❌ **no obre** |
| `<door>1</door><locknumber>1</locknumber><password></password>` | `-3` | ❌ password requerit |
| `<door>1</door><locknumber>0</locknumber><password></password>` | `-3` | ❌ password requerit |

**Conclusió:** El dispositiu accepta `set.device.opendoor` amb `error 0` però no obre amb el PIN `1993`. L'app usa `device.getUnlockPassword()` que és un password **d'obertura separat** (configurat a l'app, diferent del PIN). Pot requerir:
- El password d'obertura configurat a l'app (no el PIN)
- O una comanda prèvia `set.opendoor.checkpassword`

Format `deviceUnlock`:
```xml
<content>
  <door>1</door>
  <locknumber>1</locknumber>
  <password>{SHA256(password_d'obertura)}</password>
</content>
```

### Streaming de vídeo (càmera)

**No hi ha RTSP, snapshot CGI ni HTTP stream.** El vídeo va pel **protocol QV natiu** (port 34567):

1. `get.device.streamkey` → retorna `key` + `tdc` (verificat ✅)
2. La llibreria nativa `liblive_player.so` usa aquest token per connectar-se al port 34567
3. És un protocol propietari complex de reimplementar

`get.device.streamkey` retorna:
```xml
<key>2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va</key>
<tdc>eeccQZHXscAhwiNhHK0+zMYChvyLX/aFAElAr5FY6JxEBM8YnRFuBIc+1ft1NSMeX/...</tdc>
```

La llibreria nativa té funcions: `QVCGIConfigPreviewSnapshot`, `QVPlayerSnapshot`, `QVPlayerAttachStream` — tot dins del protocol QV, no accesible per HTTP.

### URL del stream QV (`quii://`)

De `QvDeviceCtrlCore.getUrlIpAddQv()`:
```
quii://{username}:{password}@{ip}:{port}/&ap=1
```

Exemple real per al nostre dispositiu:
```
quii://adminapp2:8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2@192.168.1.145:34567/&ap=3&tls=1
```

Variants:
- `&ap=1` → HS device
- `&ap=2` → no-HS (QvDeviceXmlParsing)
- `&ap=3` → no-HS (QvDeviceCore.getStreamUrl, amb `&tls=1` si suporta TLS)

Aquesta URL es passa a `QvJniFunc.deviceCtrlOpen(quii://...)` que fa el login al protocol QV natiu.

### Protocol QV natiu (port 34567)

- **Handshake**: espera petició del client, no envia res primer
- **Autenticació**: AES-256 (funcions `AesAuthEnc`, `sslAes256EncryptForAuthVSU`)
- **El `key`/`tdc`** de `get.device.streamkey` no es desxifren amb AES-CBC simple — protocol complex
- **Transport**: H.264 propietari via `liblive_player.so` / `libqv-p2p-v2.so`
- Les llibreries natives usen JSON amb headers `tdkcloud` (flag, command, version, client{id,type,oem,app})

**Estat**: El protocol QV natiu està documentat parcialment però és complex de reimplementar des de zero. És el mateix protocol que usa tot l'ecosistema Fermax QV.

### ✅ PROTOCOL DE LOGIN DESXIFRAT (capturat i analitzat)

Hem capturat el handshake complet amb ARP spoofing + tcpdump, i l'hem desxifrat amb la clau `2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va` (el `key` de `get.device.streamkey`).

**Clau de xifrat** (fixa per sessió):
```
2S8ofGm0VJVWRHpZ4930XxYEL5n7M3Va   (32 bytes = AES-256)
```

**Login (client → dispositiu, 208 bytes, AES-256-CBC IV nul):**
```
Header:  1O\xdd "AZ" "0000" \x80 0 \xb5 "0101" 01 [zeros]
Nonce:   8 bytes aleatoris (p2v\x1d\xc2\xdf\xa5D\xad)
Password: "24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2"
          = SHA256("1993") convertit a HEX-ASCII (64 chars, com a TEXT)
Oemid:   \x00 "G0112" \x00
Client:  "clientid=002-4112-7F950C009611492F8C4D9D73FBC56215"
          ↑ clientid real = 002-4112-{hex32}  (NO 003!)
Final:   \x00 + 32 bytes AES token
```

**Resposta (dispositiu → client):**
```
Header:  \xce_\xef "AZ" "0000" ...
Token:   "PANEL1" = tipus de dispositiu (videoporter)
```

**Stream (tots els paquets desxifrables amb la mateixa clau):**
```
Header:  [seq1 byte] "AZ" "0000" \x00 0 [seq hex 3 chars] "0000" ...
El seqüencial incrementa: .A. .B. .C. ... (0x41, 0x42, 0x43...)
Mides: 64B (headers), 1448B/1402B (frames de vídeo H.264)
```

**TROBALLA CLAU**: el clientid real del dispositiu és `002-4112-{hex}`, no `003-4112-{hex}`. Això explica per què l'OAuth cloud fallava.

### ✅ STREAM H.264 CONFIRMAT

El dispositiu envia **vídeo H.264 real** dins del stream xifrat:
- Els paquets de 1448B/1402B contenen **frames H.264** amb NAL start codes `00 00 00 01`
- S'han trobat SPS (NAL type 7), IDR i frames de vídeo
- El stream es desxifra completament amb la mateixa clau AES

**Login replay (funciona):**
- Enviar el login exacte capturat → el dispositiu respon amb 12121B+ de stream
- Canviar el password a SHA256("1993") → resposta 64B (rebutjat parcialment)
- Canviar header → rebutjat (0B)

**El dispositiu verifica:** header (bytes 0-16), nonce (32-48) i token (168-200) — són valors de sessió.
**⚠️ OBSOLET (corregit a la secció ACTUALITZACIÓ de dalt):** el password que es veia com
`24534e9f...` era un **artifact del desxifrat en cadena única** (SHA256("1993")[5:]).
Amb el desxifrat *split IV* correcte, el password és `adminapp2 && SHA256(PIN)` complet.

**Format del paquet de stream (desxifrat):**
```
[2B seq] "AZ" "0000" [flags] ... [payload]
El seqüencial incrementa per paquet (0x41, 0x42, 0x43...)
Mides: 64B (headers), 1448B/1402B (frames H.264)
```

**Arquitectura de connexió:** el client fa **2 connexions TCP** al port 34567 (ports 55757 i 55758 a la captura) — una per vídeo, una per dades/àudio.

### Login reconstruït (funciona de manera autònoma!)

Després de molta anàlisi, he reconstruït el login complet:

```
offset 0-17:   header "1O\xddAZ0000\x800\xb50101\x01" (17 bytes)
offset 17-32:  15 zero bytes
offset 32-48:  nonce (16 bytes) — fix: 7032761dc2dfa544adbe7e9b532bdc2f
offset 48-108: password (60 bytes) — "24534e9f..." + \x00
offset 108-113: "G0112" (5 bytes)
offset 113:    \x00
offset 114-165: "clientid=002-4112-7F950C009611492F8C4D9D73FBC56215\x00"
offset 165-168: \x1b!< (3 bytes)
offset 168-200: token (32 bytes) — fix: 57efac413c086567725de1c1a0663feef50c6b784ad24fc17501c107
offset 200-208: zeros
```

**Resultat de les proves:**
| Prova | Resultat |
|-------|----------|
| Replay del login exacte capturat | ✅ 220KB de stream |
| Login reconstruït amb nonce/token fix | ✅ 29KB+ (funciona!) |
| Login amb nonce/token aleatoris | ❌ 0B (rebutjat) |
| Login del login2 (nonce/token expirat) | ❌ 0B |
| Canviar només el password | ⚠️ 64B (rebutjat parcialment) |

**Conclusió:** El dispositiu accepta el **nonce/token fix** de manera **persistent i repetida** (5/5 intents amb 12-96KB). El nonce/token no caduca ràpidament. Això permet una càmera **autònoma sense el mòbil**.

**El client `qv_camera.py` funciona:** captura el stream de manera autònoma i extreu les dades H.264/QV (1 SPS + 7+ frames per sessió).

### Codi de vídeo (PENDENT)

El stream desxifrat té un **codec propietari QV** que encara no decodifiquem:
- Comença amb `00 00 01 27 4d 00 1e` que sembla un SPS H.264 (type 7, Main, level 3.0)
- Però el payload té alta entropia i PyAV no el decodifica
- NO hi ha JPEG SOI (FF D8), PNG, ni H.264 IDR (65)
- Els NALs de 3 bytes (`00 00 01`) donen type 7 (SPS) i type 1 (P-frame) però les dades no són H.264 estàndard

**Estat:** La càmera captura el stream de manera autònoma però **requereix decodificar el codec QV propietari** per mostrar imatges. És un treball de reverse engineering del codec.

---

## ✅ SOLUCIÓ TROBADA: PROJECTE `fariborz0015/quii-lan-client`

S'ha trobat un projecte a GitHub que implementa exactament el protocol quii:// i resol el codec:

- **Repo**: `github.com/fariborz0015/quii-lan-client` (Python, MIT)
- **Descripció**: "Local LAN client for Qualvision/Quvii/Briton video door stations — live video, listen, talk without the vendor cloud"
- **El mateix protocol**: port 443 CGI + 34567 media, user `adminapp2`, streamkey del CGI

### Les claus que ens faltaven

1. **IV = 16 bytes ASCII `'0'`** (0x30), NO zeros binaris!
2. **Password del wire = `adminapp2 && SHA256(PIN)`** (NO SHA256(auth_code)) — vegeu la secció ACTUALITZACIÓ de dalt. El projecte de referència usa SHA256(auth_code) per a dispositius Briton/Qualvision; el Fermax See-U usa el SHA256 del PIN del dispositiu.
3. **Framing de 32 bytes** amb opcodes: `0xA9` setup, `0x01` play, `0xA0-0xA3` media
4. **URL**: `quii://USER:PASS@IP:PORT/mode=real&idc=1&ids=2&ap=2`
5. **Frame header**: `00 00 01 E0+type` + payload length + codec

### ✅ VERIFICAT FUNCIONANT

```
msg[4] cmd=0xA0 media body_len=2697
SAVED frame.h264 (keyframe)
Frame decodificat: 352x240
JPEG: 9845B — vídeo real (5033 colors únics)
```

### Com funciona (el flux)

1. TCP connect al port 34567
2. **Setup**: 32 bytes, `hdr[0]=0xA9`
3. **Play**: `hdr[0]=0x01`, body `user&&pass\0` + clientid
4. **Media**: paquets `0xA0` amb frames H.264
5. **KeepAlive** cada ~8s

### Anàlisi de seguretat (fet abans d'executar)

- ✅ Codi net, cap malware
- ✅ Imports: només stdlib + cryptography + Flask
- ✅ `subprocess`: només executa ffmpeg per convertir vídeo
- ✅ Connexions: només al dispositiu local
- ✅ Cap exec/eval, cap exfiltració

### La imatge capturada

`frame_camera.jpg` — primera imatge real de la càmera del videoporter (352x240).

---

## ✅ CLIENT AUTÒNOM DE CÀMERA (`seeu_camera.py`)

He creat un client autònom que captura frames JPEG sense necessitat del mòbil:

```bash
python3 seeu_camera.py 192.168.1.145 /tmp/frame.jpg
```

**Verificat estable**: 4 captures seguides, totes amb èxit (~10KB JPEG, 352x240).

### Com funciona

1. TCP connect al port 34567
2. Setup (`0xA9`)
3. Play (replay del login capturat — el dispositiu l'accepta de manera persistent)
4. Parseja els paquets media `0xA0`-`0xA3`
5. Extreu el keyframe H.264
6. Decodifica a JPEG amb PyAV

### Integració HA

- `custom_components/fermax_seeu/direct_camera.py` — mòdul de càmera directa
- `camera.py` — usa la connexió directa quan hi ha `device_ip`
- `manifest.json` — afegeix `av` (PyAV) com a dependència

### Repte futur

El login capturat (replay) funciona de manera **persistent** (el dispositiu l'accepta repetidament). Si eventualment caduca, caldrà:
1. Reconstruir el login amb el password correcte (SHA256 del PIN) + ts/token fixos — **FET**, vegeu la secció ACTUALITZACIÓ de dalt
2. O capturar una sessió fresca per actualitzar el nonce/token

### El SDK QV = SDK Dahua/XiongMai (neteja de símbols)

La llibreria `liblive_player.so` conté símbols del **SDK Dahua/XiongMai**:
- `SDK_Login`, `SDK_RealPlay`, `SDK_StopRealPlay`
- `SDK_PlayBackByTime`, `SDK_SearchDevices`
- `CQVPwdAuthInfo` (username/password/bucket/region), `GetStreamLoginID(RV_RealPlayType)`

Això significa que el protocol de streaming podria ser una variant del **protocol Dahua** (que té moltes implementacions open-source en Python). El port 34567, però, usa un handshake propietari QV que no és Dahua pur (no respon a login Dahua estàndard).

### Via cloud (mediasoup) — ja implementada a la integració

La integració actual (`streaming.py`) usa el signaling server `signaling-pro-duoxme.fermax.io` + mediasoup per rebre els frames de vídeo. Aquesta via **funcionaria si l'autenticació cloud funcionés** — però l'OAuth cloud no funciona amb el QR (invalid_grant).

Flux cloud:
1. `POST /deviceaction/api/v2/device/{id}/autoon` → push notification amb roomId + signalingUrl
2. Socket.IO connect → join_call → transport params
3. pymediasoup → RecvTransport → frames H.264 → JPEG

**Blocador**: requereix access_token OAuth cloud (no disponible per QR).

---

## 📱 TRÀFIC CAPTURAT AMB MITMPROXY

### Petició local al dispositiu (get.device.status) — funciona

```xml
<?xml version="1.0" encoding="UTF-8"?>
<envelope>
  <header>
    <security>username</security>
    <username>adminapp2</username>
    <password>8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2</password>
    <passwordencode>1</passwordencode>
  </header>
  <body>
    <command>get.device.status</command>
    <content/>
  </body>
</envelope>
```

### Petició de canvi de password (set.seurity.verifycode) — falla "Fail to Modify"

```xml
<command>set.seurity.verifycode</command>
<content>
  <old>8e71b24534e9f3fb3a71263359fed2b7ffb008265e0d34383e319f1b6f5c08f2</old>   <!-- SHA256(1993) -->
  <new>7e5b72c6fcb592801b313e09238321734c863536946a46642c855bb9ca6a1e87</new>   <!-- SHA256(3991), el que es va provar -->
  <acountid>0</acountid>
  <bencode>true</bencode>
</content>
```

> Nota: la comanda té la typo `seurity` (al firmware del dispositiu). El nou hash `7e5b72c6...` = SHA256 d'algun password; no es va poder revertir amb candidats comuns, però l'usuari va confirmar que provava `3991`.

### Altres tràfic

- `ios.bugly.qq.com` → SDK de reports de crashes (Tencent Bugly), **no rellevant**
- **Error**: `Certificate verify failed: EE certificate key too weak` → els servidors Fermax cloud tenen certs SSL febles que mitmproxy es nega a desxifrar

---

## 🛠️ QUÈ S'HA PROVAT I QUÈ HA FUNCIONAT

### ✅ HA FUNCIONAT

1. **Connexió directa al dispositiu** via `POST https://192.168.1.145/tdkcgi` amb `get.device.status` → **200 OK** amb dades reals
2. **Client credentials cloud** (`dpv7iqz...:c7ylkqpujwah85yh...`) → **reconeguts** pel servidor OAuth (retorna `invalid_grant`, no `invalid_client`)
3. `get.device.status` via l'app → tràfic capturat

### ❌ NO HA FUNCIONAT

1. OAuth password grant amb qualsevol combinació de camps del QR (308 combinacions) → `invalid_grant`
2. `dev-bind-register` XML (totes les variants) → `400` / `405` / `404`
3. `GET/POST /qvoauthv2/token` → HTML login / `403`
4. Canvi de password del dispositiu (`set.seurity.verifycode`) → "Fail to Modify"
5. OAuth cloud `client_credentials` → `unauthorized_client`

---

## 🚀 SEGÜENTS PASSOS

1. **Provar `set.device.opendoor`** (obrir porta) directament al dispositiu
2. **Provar el streaming de càmera** (RTSP/MJPEG via P2P o directe)
3. **Reescriure la integració** per connectar-se directament al dispositiu (LAN) en lloc del cloud
4. La integració HA hauria de:
   - Connectar-se a `https://{device_ip}/tdkcgi`
   - Usar `adminapp2` + `SHA256(pin)`
   - Suportar `get.device.status`, `set.device.opendoor`, streaming, etc.

---

## 📁 FITXERS RELACIONATS

- `test_device.py` — prova de connexió directa al dispositiu (funciona)
- `test_auth_qr.py` — proves d'autenticació OAuth cloud
- `test_exhaustive.py` — 308 combinacions de credencials QR
- `test_diagnose.py` — diagnòstic de l'OAuth cloud
- `credentials_seeu.json` — credencials Firebase + API
- `custom_components/fermax_seeu/` — la integració (a adaptar)
