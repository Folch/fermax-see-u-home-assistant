"""Constants for the Fermax See-U integration."""

from __future__ import annotations

DOMAIN = "fermax_seeu"
MANUFACTURER = "Fermax"

# Simulated device headers (See-U)
APP_HEADERS = {
    "app-version": "1.0.1",
    "accept-language": "en-ES;q=1.0, es-ES;q=0.9",
    "phone-os": "14.0",
    "user-agent": ("See-U/1.0.1 (com.fermax.see.u; build:1; iOS 14.0)"),
    "phone-model": "HA-Integration",
    "app-build": "1",
}

# Signal dispatchers
SIGNAL_DOORBELL_RING = f"{DOMAIN}_doorbell_ring_{{}}_{{}}"
SIGNAL_CALL_ENDED = f"{DOMAIN}_call_ended_{{}}"
SIGNAL_DOOR_OPENED = f"{DOMAIN}_door_opened_{{}}"
SIGNAL_CAMERA_ON = f"{DOMAIN}_camera_on_{{}}"
SIGNAL_DIRECT_STREAM_CHANGED = f"{DOMAIN}_direct_stream_changed_{{}}"

# Platforms
PLATFORMS = [
    "binary_sensor",
    "button",
    "camera",
    "event",
    "lock",
    "number",
    "select",
    "sensor",
    "switch",
]

# Call mode options (select entity)
CALL_MODE_NOTIFY = "notify_only"
CALL_MODE_RECORD = "record"
CALL_MODE_AUTO_RESPOND = "auto_respond"
CALL_MODES = [CALL_MODE_NOTIFY, CALL_MODE_RECORD, CALL_MODE_AUTO_RESPOND]

# Stream duration limits (seconds) — also the direct-LAN keep-alive after the
# "Camera preview" button, matching the vendor app's ~1 min auto-stop.
DEFAULT_STREAM_DURATION = 60
MIN_STREAM_DURATION = 10
MAX_STREAM_DURATION = 120

# Config keys — QR registration parameters
CONF_QR_USER_ID = "qr_user_id"              # u field from QR
CONF_QR_ACCOUNT_ID = "qr_account_id"        # a field from QR
CONF_QR_DEVICE_ID = "qr_device_id"          # d field from QR
CONF_QR_MAC = "qr_mac"                      # b field (MAC address)
CONF_QR_MODEL = "qr_model"                  # m field from QR
CONF_QR_CODE = "qr_code"                    # c field from QR
CONF_QR_JSON = "qr_json"                    # Raw JSON from QR

# Config keys — direct LAN connection (See-U)
CONF_DEVICE_IP = "device_ip"                # IP of the videoporter on the LAN
CONF_DEVICE_PIN = "device_pin"              # Device PIN (e.g. "1234")
CONF_DEVICE_USERNAME = "device_username"    # CGI username (adminapp2)

# API/Firebase credentials (same as Blue, for now)
CONF_FERMAX_AUTH_URL = "fermax_auth_url"
CONF_FERMAX_BASE_URL = "fermax_base_url"
CONF_FERMAX_AUTH_BASIC = "fermax_auth_basic"
CONF_FIREBASE_API_KEY = "firebase_api_key"
CONF_FIREBASE_SENDER_ID = "firebase_sender_id"
CONF_FIREBASE_APP_ID = "firebase_app_id"
CONF_FIREBASE_PROJECT_ID = "firebase_project_id"
CONF_FIREBASE_PACKAGE_NAME = "firebase_package_name"

# Options flow defaults
DEFAULT_SCAN_INTERVAL = 5  # minutes
MIN_SCAN_INTERVAL = 1
MAX_SCAN_INTERVAL = 30
CONF_SCAN_INTERVAL = "scan_interval"
CONF_RECORDING_RETENTION = "recording_retention"
DEFAULT_RECORDING_RETENTION = 10  # days
RECORDINGS_DIR = "fermax_recordings"

# Watchdog poll interval (seconds) for the FCM push receiver.
FCM_WATCHDOG_INTERVAL = 60
