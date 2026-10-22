# Fermax See-U per Home Assistant

Integració de **Fermax See-U** per a Home Assistant (clonat de Fermax Blue).

## ✅ Setup Completat

Aquesta integració ja té totes les credencials configurades:

### Credencials OAuth (Fermax API)

- **Auth URL**: `https://oauth-pro-duoxme.fermax.io`
- **Base URL**: `https://pro-duoxme.fermax.io`
- **Auth Basic**: Ja configurad (client_id:client_secret en Base64)

### Firebase Credentials (See-U)

- **API Key**: Extret de l'APK de Fermax See-U v1.0.1
- **Sender ID**: 673285852721
- **App ID**: 1:673285852721:android:464de0dca8be306d490f10
- **Project ID**: fermax-see-u
- **Package Name**: com.fermax.see.u

## � QR Registration

Fermax See-U usa **registre via QR sense email/password**.

Quan escaneges el QR, obté informació com:

```json
{
  "v": 1,
  "u": "25025kt9aysi", // User ID (pots usar-ho a HA)
  "c": "VKMFNOIO",
  "m": "IDS94C3W",
  "a": "IDS94C3Waysi",
  "d": "b0211111",
  "b": "e8:5c:5f:a0:2b:d8"
}
```

## 🚀 Com usar

### 1. Setup a Home Assistant

```bash
# Copia la integració a Home Assistant
cp -r custom_components/fermax_seeu ~/.homeassistant/custom_components/
```

### 2. Reinicia Home Assistant

```
Settings → System → System Options → Restart Home Assistant
```

### 3. Afegeix la integració

```
Settings → Devices & Services → Add Integration → Fermax See-U
```

**En el config flow:**

- **User ID (optional)**: Pots deixar buit, o entrar el valor `u` del QR
- **Password**: Deixa buit

Els credentials OAuth i Firebase estàn pre-configurats!

### 4. Validació

Si tot està bé, la integració es crearà i es connectarà a Fermax See-U via Firebase.

## 📋 Estructura de la Integració

```
custom_components/fermax_seeu/
├── api.py                   - Client API de Fermax
├── coordinator.py           - Coordinador de dades
├── config_flow.py           - Setup flow
├── const.py                 - Constants (DOMAIN=fermax_seeu)
├── manifest.json            - Metadata
├── strings.json             - Translations
├── camera.py                - Camera entity
├── lock.py                  - Door lock
├── button.py                - Action buttons
├── switch.py                - Binary switches
├── sensor.py                - Status sensors
├── event.py                 - Event generation
├── notification.py          - Firebase push notifications
└── [altres entitats]        - Binary sensors, numbers, etc.
```

## 🔐 Nota sobre Credencials

Els credentials OAuth (`fermax_auth_basic`) sòn els mateixos que per a Fermax Blue (públicament descoberts per la comunitat).

See-U i Blue comparteixen la **mateixa API** (`pro-duoxme.fermax.io`), així que els credentials i endpoints sòn idèntics.

**Diferència clau**: See-U usa **registre via QR** en lloc de email/password tradicional.

## 📚 Funcionalitats

- ✅ QR-based registration (sense email/password)
- ✅ Notificacions Firebase en temps real (doorbell ring)
- ✅ Streaming MJPEG en viu
- ✅ Obrir porta remotament
- ✅ Control de F1 (botó auxiliar)
- ✅ Crida a porteria
- ✅ Do Not Disturb
- ✅ Historial d'obertures
- ✅ Estat de connexió
- ✅ Senyal WiFi
- ✅ Control de notificacions
- ✅ Media browser (fotos i gravacions)
- ✅ Diagnòstics

## 🐛 Suport

En cas de problemes:

1. Verifica que has escanejat correctament el QR
2. Assegura't que Firebase credentials sòn correctes
3. Revisa els logs de Home Assistant

## 📝 Origen

Clonat de: [bvis/fermax-blue-hass](https://github.com/bvis/fermax-blue-hass)

Adaptació per a Fermax See-U (que usa la mateixa API que Blue però amb registre via QR).
