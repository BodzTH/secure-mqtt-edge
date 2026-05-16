# secure-mqtt-edge

Secure MQTT edge demo using **ESP32 publishers** (Arduino/C++) and **Python subscribers** to transmit:
- **Encrypted DHT11 temperature & humidity**
- **Encrypted ESP32-CAM JPEG images** (request-based capture)

The project demonstrates an **Encrypt-then-MAC** design over MQTT:
- **Encryption:** AES-128-CBC (with PKCS7 padding)
- **Integrity/Authentication:** HMAC-SHA256 computed **over ciphertext only**
- **Packet format (both flows):** `HMAC(32) | IV(16) | CIPHERTEXT(N)`

## Repository layout

- `publisher/`
  - `dht11/` — ESP32 + DHT11 secure telemetry publisher
  - `cam/` — ESP32-CAM secure image publisher (capture on request)
- `subscriber/`
  - `subscriber_dht11.py` — Tkinter dashboard that verifies HMAC, decrypts payload, and shows live sensor values
  - `subscriber_cam.py` — Tkinter viewer that requests capture, verifies HMAC, decrypts JPEG, and displays it

## MQTT topics

### DHT11 telemetry
- Publish topic: `esp32/dht11/encrypted`

### ESP32-CAM images (request/response)
- Subscriber → publisher request topic: `esp32cam/request` (payload: `capture`)
- Publisher → subscriber image topic: `esp32cam/encrypted_image`

## Security design (high level)

1. Device prepares plaintext (sensor string or JPEG bytes)
2. Device generates random **IV (16 bytes)**
3. Device encrypts with **AES-128-CBC**
4. Device computes **HMAC-SHA256 over the ciphertext**
5. Device publishes: `HMAC | IV | ciphertext`
6. Subscriber:
   - verifies HMAC first (rejects if invalid)
   - decrypts only if HMAC is valid
   - removes PKCS7 padding
   - displays decoded content

## Prerequisites

### MQTT broker
- A Mosquitto broker reachable by both ESP32 and the Python machine.
- Default port used: `1883`

### Python subscriber requirements
The subscribers use:
- `paho-mqtt`
- `cryptography`
- `Pillow` (camera subscriber)
- Tkinter (usually included with Python on many systems)

Example install:
```bash
pip install paho-mqtt cryptography pillow
```

## Running the subscribers (Python)

> Both subscriber scripts default to `MQTT_BROKER = "127.0.0.1"`.
> If your broker is on another machine, change it (the code comments mention e.g. `192.168.10.20`).

### DHT11 dashboard
```bash
python subscriber/subscriber_dht11.py
```

### ESP32-CAM viewer
```bash
python subscriber/subscriber_cam.py
```

In the camera viewer, press **Capture** to publish `capture` to `esp32cam/request`.

## Building/flashing the publishers (ESP32 / Arduino)

The ESP32 sketches are:
- `publisher/dht11/dht11.ino`
- `publisher/cam/cam.ino`

They reference an `esp32-secrets.h` header for Wi‑Fi, broker IP, and cryptographic keys. You’ll need to create that file locally in the sketch folder (it is intentionally not present in the repo).

### Expected secrets
Both sketches use:
- `SECRET_SSID`
- `SECRET_PASS`
- `SECRET_IP` (MQTT broker IP/hostname)
- `SECRET_AES_KEY` (16 bytes)
- `SECRET_HMAC_KEY` (bytes/string)

## Notes / limitations

- This is a learning/demo project and uses **pre-shared keys** in code (or a local header). For production, consider secure provisioning, key rotation, broker auth/TLS, and device identity management.
- AES-CBC + HMAC is implemented as Encrypt-then-MAC correctly here, but modern designs often use AEAD modes (e.g., AES-GCM / ChaCha20-Poly1305) to simplify usage and reduce misuse risk.

---
**Components**
- ESP32 DHT11 secure publisher + Python live dashboard subscriber
- ESP32-CAM secure publisher (capture on request) + Python GUI viewer subscriber
