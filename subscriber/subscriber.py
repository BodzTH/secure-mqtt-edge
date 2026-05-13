"""
============================================================
  Python MQTT Subscriber — IoT Security Project
  Laptop B (Subscriber)  IP: 192.168.10.30
  Broker : 192.168.10.20 : 1883

  Topics:
    Temperature : esp32/dht11/encrypted
    Camera image: esp32cam/encrypted_image

  Security:
    Decryption : AES-128-CBC
    Integrity  : HMAC-SHA256
    Anti-replay: seq_num (uint32) + timestamp (uint64 ms)
                 30-second freshness window

  ── Assumed wire format ─────────────────────────────────────
    [0..3]   seq_num    uint32 big-endian
    [4..11]  timestamp  uint64 big-endian  (Unix ms)
    [12..43] HMAC-SHA256  32 bytes
    [44..59] IV           16 bytes  (AES-CBC nonce)
    [60..]   ciphertext   N bytes   (AES-128-CBC, PKCS7 padded)

  Install dependencies:
    pip install paho-mqtt cryptography pillow
============================================================
"""

import struct
import time
import json
import hmac as hmac_lib
import hashlib
import sys
import os
from datetime import datetime

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

try:
    from PIL import Image
    import io
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    print("[WARN] Pillow not installed — images saved to disk only.")
    print("[WARN] Run: pip install pillow\n")


# ══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════

BROKER_HOST   = "127.0.0.1"
BROKER_PORT   = 1883
CLIENT_ID     = "subscriber"
MQTT_USERNAME = None    # set to "subscriber" if broker has auth
MQTT_PASSWORD = None    # set to your password if broker has auth

TOPIC_TEMP  = "esp32/dht11/encrypted"
TOPIC_IMAGE = "esp32cam/encrypted_image"

# ── Confirmed crypto keys ─────────────────────────────────────
AES_KEY = bytes([
    0x10, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x11
])  # 16 bytes = AES-128

HMAC_KEY = b"ESP32_SECRET_HMAC_KEY"

# ── Anti-replay state ─────────────────────────────────────────
TIMESTAMP_WINDOW_SEC = 30
last_seq = {}   # { "temp" | "image" : last_seq_num }

# ── Packet byte offsets ───────────────────────────────────────
OFF_SEQ  = 0    # 4 bytes
OFF_TS   = 4    # 8 bytes
OFF_HMAC = 12   # 32 bytes
OFF_IV   = 44   # 16 bytes
OFF_CT   = 60   # ciphertext starts here
MIN_LEN  = 61   # minimum valid packet

# ── Image output folder ───────────────────────────────────────
IMAGE_DIR = "received_images"
os.makedirs(IMAGE_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  CRYPTO HELPERS
# ══════════════════════════════════════════════════════════════

def verify_hmac(raw: bytes) -> bool:
    """
    Verifies HMAC-SHA256 over the entire packet except the HMAC field.
    Covered data = seq(4) + ts(8) + IV(16) + ciphertext.
    Uses hmac.compare_digest to block timing side-channel attacks.
    """
    received = raw[OFF_HMAC : OFF_HMAC + 32]
    covered  = raw[:OFF_HMAC] + raw[OFF_HMAC + 32:]
    expected = hmac_lib.new(HMAC_KEY, covered, hashlib.sha256).digest()
    return hmac_lib.compare_digest(received, expected)


def aes128_cbc_decrypt(ciphertext: bytes, iv: bytes) -> bytes | None:
    """AES-128-CBC decrypt + PKCS7 unpad. Returns plaintext or None."""
    try:
        cipher    = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv),
                           backend=default_backend())
        decryptor = cipher.decryptor()
        padded    = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder  = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception as e:
        print(f"  [CRYPTO] Decryption error: {e}")
        return None


def check_replay(key: str, seq: int, ts_ms: int) -> tuple[bool, str]:
    """
    Anti-replay: checks timestamp freshness AND seq monotonicity.
    Returns (is_valid, reason_string).
    """
    age = abs(time.time() - ts_ms / 1000.0)
    if age > TIMESTAMP_WINDOW_SEC:
        return False, f"stale timestamp (age={age:.1f}s > {TIMESTAMP_WINDOW_SEC}s)"
    if key in last_seq and seq <= last_seq[key]:
        return False, f"seq={seq} not greater than last seen={last_seq[key]}"
    return True, "ok"


def parse_header(raw: bytes) -> tuple[int, int, bytes, bytes] | None:
    """Extract seq, ts_ms, iv, ciphertext from raw packet. Returns None if malformed."""
    if len(raw) < MIN_LEN:
        print(f"  [ERR] Packet too short ({len(raw)} < {MIN_LEN} bytes)")
        return None
    seq   = struct.unpack_from(">I", raw, OFF_SEQ)[0]
    ts_ms = struct.unpack_from(">Q", raw, OFF_TS)[0]
    iv    = raw[OFF_IV : OFF_IV + 16]
    ct    = raw[OFF_CT:]
    if len(iv) != 16:
        print("  [ERR] IV is not 16 bytes")
        return None
    if len(ct) == 0 or len(ct) % 16 != 0:
        print(f"  [ERR] Ciphertext length {len(ct)} is not a non-zero multiple of 16")
        return None
    return seq, ts_ms, iv, ct


# ══════════════════════════════════════════════════════════════
#  TEMPERATURE HANDLER
# ══════════════════════════════════════════════════════════════

def handle_temperature(raw: bytes):
    print(f"\n{'━'*54}")
    print(f"  📡  TEMPERATURE  ({len(raw)} bytes)")
    print(f"{'━'*54}")

    parsed = parse_header(raw)
    if parsed is None:
        return
    seq, ts_ms, iv, ct = parsed
    print(f"  seq={seq}   ts_ms={ts_ms}   ct_len={len(ct)}")

    if not verify_hmac(raw):
        print("  [SECURITY] ❌ HMAC FAILED — payload tampered or wrong key!")
        return
    print("  [SECURITY] ✓ HMAC-SHA256 verified")

    ok, reason = check_replay("temp", seq, ts_ms)
    if not ok:
        print(f"  [SECURITY] ❌ REPLAY BLOCKED — {reason}")
        return
    print(f"  [SECURITY] ✓ Anti-replay passed (seq={seq})")
    last_seq["temp"] = seq

    plaintext = aes128_cbc_decrypt(ct, iv)
    if plaintext is None:
        print("  [ERR] Decryption failed — message dropped.")
        return
    print(f"  [CRYPTO]   ✓ Decrypted {len(ct)} → {len(plaintext)} bytes")

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"  [ERR] JSON parse failed: {e}")
        print(f"  [ERR] Raw plaintext hex: {plaintext.hex()}")
        return

    ts_str = datetime.fromtimestamp(ts_ms / 1000).strftime("%H:%M:%S")
    print()
    print(f"  ┌─ Sensor Reading ──────────────────────────────")
    print(f"  │  Device      : {data.get('device', 'esp32')}")
    print(f"  │  Temperature : {data.get('temp', '?')} °{data.get('unit', 'C')}")
    print(f"  │  Humidity    : {data.get('hum', '?')} %")
    print(f"  │  Sequence #  : {seq}")
    print(f"  │  Time        : {ts_str}")
    print(f"  └───────────────────────────────────────────────")


# ══════════════════════════════════════════════════════════════
#  IMAGE HANDLER
# ══════════════════════════════════════════════════════════════

def handle_image(raw: bytes):
    print(f"\n{'━'*54}")
    print(f"  📷  IMAGE  ({len(raw)} bytes)")
    print(f"{'━'*54}")

    parsed = parse_header(raw)
    if parsed is None:
        return
    seq, ts_ms, iv, ct = parsed
    print(f"  seq={seq}   ts_ms={ts_ms}   ct_len={len(ct)}")

    if not verify_hmac(raw):
        print("  [SECURITY] ❌ HMAC FAILED — image tampered or wrong key!")
        return
    print("  [SECURITY] ✓ HMAC-SHA256 verified")

    ok, reason = check_replay("image", seq, ts_ms)
    if not ok:
        print(f"  [SECURITY] ❌ REPLAY BLOCKED — {reason}")
        return
    print(f"  [SECURITY] ✓ Anti-replay passed (seq={seq})")
    last_seq["image"] = seq

    image_bytes = aes128_cbc_decrypt(ct, iv)
    if image_bytes is None:
        print("  [ERR] Decryption failed — image dropped.")
        return
    print(f"  [CRYPTO]   ✓ Decrypted {len(ct)} → {len(image_bytes)} bytes")

    # Save to disk
    tag      = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(IMAGE_DIR, f"image_{tag}_seq{seq}.jpg")
    with open(filepath, "wb") as f:
        f.write(image_bytes)
    print(f"  [IMAGE]    ✓ Saved: {filepath}")

    # Display with Pillow
    if PILLOW_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.show()
            print(f"  [IMAGE]    Opened in viewer ({img.size[0]}x{img.size[1]} px)")
        except Exception as e:
            print(f"  [IMAGE]    Could not display: {e} — file saved, open manually.")

    ts_str = datetime.fromtimestamp(ts_ms / 1000).strftime("%H:%M:%S")
    print()
    print(f"  ┌─ Image Received ──────────────────────────────")
    print(f"  │  Size        : {len(image_bytes):,} bytes")
    print(f"  │  Sequence #  : {seq}")
    print(f"  │  Time        : {ts_str}")
    print(f"  │  Saved to    : {filepath}")
    print(f"  └───────────────────────────────────────────────")


# ══════════════════════════════════════════════════════════════
#  MQTT CALLBACKS
# ══════════════════════════════════════════════════════════════

def on_connect(client, userdata, flags, reason_code, properties):
    rc = reason_code
    if rc == 0:
        print(f"[MQTT] ✓ Connected to {BROKER_HOST}:{BROKER_PORT}")
        client.subscribe(TOPIC_TEMP,  qos=1)
        client.subscribe(TOPIC_IMAGE, qos=1)
        print(f"[MQTT] Subscribed → {TOPIC_TEMP}")
        print(f"[MQTT] Subscribed → {TOPIC_IMAGE}")
        print("[MQTT] Waiting for messages...\n")
    else:
        msgs = {1:"bad protocol",2:"client ID rejected",
                3:"broker unavailable",4:"bad credentials",5:"not authorised"}
        print(f"[MQTT] ✗ Connect failed: {msgs.get(rc, f'rc={rc}')}")


def on_disconnect(client, userdata, flags, reason_code, properties):
    if rc != 0:
        print(f"[MQTT] Unexpected disconnect (rc={rc}) — will reconnect automatically.")


def on_message(client, userdata, msg):
    raw = bytes(msg.payload)
    try:
        if msg.topic == TOPIC_TEMP:
            handle_temperature(raw)
        elif msg.topic == TOPIC_IMAGE:
            handle_image(raw)
        else:
            print(f"[MQTT] Unknown topic: {msg.topic} — ignored.")
    except Exception as e:
        print(f"[ERR] Unhandled exception in message handler: {e}")


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    assert len(AES_KEY) == 16, "AES_KEY must be exactly 16 bytes for AES-128"

    print("=" * 54)
    print("  IoT Subscriber — AES-128-CBC + HMAC-SHA256")
    print(f"  Broker   : {BROKER_HOST}:{BROKER_PORT}")
    print(f"  Topics   : {TOPIC_TEMP}")
    print(f"           : {TOPIC_IMAGE}")
    print(f"  AES key  : {AES_KEY.hex()}")
    print(f"  HMAC key : {HMAC_KEY.decode()}")
    print(f"  Images   → ./{IMAGE_DIR}/")
    print("=" * 54 + "\n")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=CLIENT_ID, clean_session=False)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    print(f"[MQTT] Connecting to {BROKER_HOST}:{BROKER_PORT}...")
    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[MQTT] Stopped by user.")
        client.disconnect()
    except ConnectionRefusedError:
        print(f"\n[FATAL] Connection refused — is Mosquitto running on {BROKER_HOST}:{BROKER_PORT}?")
        sys.exit(1)
    except OSError as e:
        print(f"\n[FATAL] Network error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
