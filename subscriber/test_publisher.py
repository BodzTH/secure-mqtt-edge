"""
Test Publisher — simulates the ESP32 sending encrypted messages.
Run this AFTER mosquitto and subscriber.py are both running.

Usage:
    python test_publisher.py
"""

import struct
import time
import json
import hmac as hmac_lib
import hashlib
import os
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ── Must match subscriber.py exactly ─────────────────────────
BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883

AES_KEY = bytes([
    0x10, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x11
])

HMAC_KEY    = b"ESP32_SECRET_HMAC_KEY"
TOPIC_TEMP  = "esp32/dht11/encrypted"
TOPIC_IMAGE = "esp32cam/encrypted_image"

seq = 0  # global sequence counter


def build_packet(plaintext_bytes: bytes) -> bytes:
    """
    Encrypts plaintext and builds the full binary packet:
    seq(4) + ts(8) + HMAC(32) + IV(16) + ciphertext(N)
    """
    global seq
    seq += 1

    ts_ms = int(time.time() * 1000)

    # AES-128-CBC: pad plaintext to multiple of 16 bytes
    padder  = padding.PKCS7(128).padder()
    padded  = padder.update(plaintext_bytes) + padder.finalize()

    # Random 16-byte IV
    iv = os.urandom(16)

    # Encrypt
    cipher    = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Build packet without HMAC first
    seq_bytes = struct.pack(">I", seq)       # uint32 big-endian
    ts_bytes  = struct.pack(">Q", ts_ms)     # uint64 big-endian

    # HMAC covers: seq + ts + IV + ciphertext  (everything except the HMAC field)
    data_to_mac = seq_bytes + ts_bytes + iv + ciphertext
    mac = hmac_lib.new(HMAC_KEY, data_to_mac, hashlib.sha256).digest()

    # Final packet: seq + ts + HMAC + IV + ciphertext
    packet = seq_bytes + ts_bytes + mac + iv + ciphertext
    return packet


def send_temperature(client):
    payload = {
        "device": "esp32temp",
        "temp":   24.5,
        "hum":    58.3,
        "seq":    seq + 1,
        "ts":     int(time.time()),
        "unit":   "C"
    }
    plaintext = json.dumps(payload).encode("utf-8")
    packet    = build_packet(plaintext)
    client.publish(TOPIC_TEMP, packet, qos=1)
    print(f"[PUB] Temperature sent (seq={seq}, {len(packet)} bytes)")


def send_fake_image(client):
    # Simulate a tiny JPEG-like binary blob (real ESP32 sends actual JPEG)
    fake_jpeg = bytes([0xFF, 0xD8, 0xFF, 0xE0] + [0xAB] * 200 + [0xFF, 0xD9])
    packet    = build_packet(fake_jpeg)
    client.publish(TOPIC_IMAGE, packet, qos=1)
    print(f"[PUB] Image sent (seq={seq}, {len(packet)} bytes)")


def main():
    print("=" * 45)
    print("  Test Publisher (simulates ESP32)")
    print(f"  Broker: {BROKER_HOST}:{BROKER_PORT}")
    print("=" * 45 + "\n")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id="test_esp32")
    client.connect(BROKER_HOST, BROKER_PORT)
    client.loop_start()
    time.sleep(0.5)

    print("Sending 3 temperature messages then 1 image...\n")

    for i in range(3):
        send_temperature(client)
        time.sleep(2)

    send_fake_image(client)

    time.sleep(1)
    client.loop_stop()
    client.disconnect()
    print("\n[DONE] All test messages sent.")


if __name__ == "__main__":
    main()
