# ESP32-CAM Secure Publisher

Request-based secure JPEG transmission from an ESP32-CAM to an MQTT broker.

## What it does

- Subscribes to a request topic
- When it receives the message `capture`:
  1. Captures a JPEG frame from the camera
  2. Generates a random IV (16 bytes)
  3. Encrypts the JPEG bytes with **AES-128-CBC**
  4. Computes **HMAC-SHA256 over the ciphertext** (Encrypt-then-MAC)
  5. Publishes the binary packet to the image topic

## MQTT topics

- Request topic (subscribe): `esp32cam/request`  
  Expected payload: `capture`

- Image topic (publish): `esp32cam/encrypted_image`  
  Payload (binary): `HMAC(32) | IV(16) | CIPHERTEXT(N)`

## Crypto / packet format

- AES: 128-bit key, CBC mode, PKCS7 padding
- HMAC: SHA-256, computed over ciphertext only

Packet layout:
- bytes `[0:32]`   → HMAC-SHA256
- bytes `[32:48]`  → IV
- bytes `[48:...]` → ciphertext

## Dependencies

- Arduino core for ESP32
- `ArduinoMqttClient` (used for MQTT)
- `esp_camera` (ESP32-CAM camera driver; typically provided via ESP32 Arduino core)
- mbedTLS (used for AES + HMAC; available in ESP32 toolchain)

## Secrets / configuration (`esp32-secrets.h`)

This sketch expects an `esp32-secrets.h` containing:
- `SECRET_SSID`
- `SECRET_PASS`
- `SECRET_IP` (MQTT broker IP/hostname)
- `SECRET_AES_KEY` (16 bytes)
- `SECRET_HMAC_KEY`

## Implementation notes

The sketch includes fixes/optimizations important for ESP32-CAM:
- Uses PSRAM allocations for larger buffers (helps avoid crashes on big frames)
- Flushes a stale framebuffer frame before the “real” capture (reduces dark photos)
- Turns on the flash LED briefly during capture

## How to test

1. Start a Mosquitto broker reachable by ESP32 and the subscriber PC.
2. Run the Python camera subscriber (`subscriber/subscriber_cam.py`).
3. Flash this sketch to the ESP32-CAM.
4. In the Python UI, press **Capture** → the ESP32-CAM should publish an encrypted image.
