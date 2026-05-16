# Subscriber (Python)

This folder contains the **Python subscribers** that:
- Subscribe to encrypted MQTT topics
- Verify **HMAC-SHA256 over ciphertext** (Encrypt-then-MAC)
- Decrypt using **AES-128-CBC**
- Display results in a Tkinter GUI

## Scripts

### `subscriber_dht11.py` — DHT11 dashboard
- Subscribes to: `esp32/dht11/encrypted`
- Expects packet: `HMAC(32) | IV(16) | ciphertext`
- After successful verification/decryption, expects plaintext like:
  - `T:24.50,H:61.20`
- Displays temperature/humidity + security stats (HMAC OK/FAIL counters)

Run:
```bash
python subscriber_dht11.py
```

### `subscriber_cam.py` — ESP32-CAM viewer
- Subscribes to: `esp32cam/encrypted_image`
- Publishes capture requests to: `esp32cam/request` (payload: `capture`)
- Expects packet: `HMAC(32) | IV(16) | ciphertext`
- Decrypts to raw JPEG bytes and displays them using Pillow + Tkinter

Run:
```bash
python subscriber_cam.py
```

## Configuration

Both scripts have a clearly marked configuration section near the top, including:
- `MQTT_BROKER` (defaults to `127.0.0.1`)
- `MQTT_PORT` (defaults to `1883`)
- Topic names
- `AES_KEY` and `HMAC_KEY`

If your Mosquitto broker is not local, update `MQTT_BROKER` accordingly.

## Python dependencies

Install:
```bash
pip install paho-mqtt cryptography pillow
```

Notes:
- `subscriber_dht11.py` does not require Pillow.
- Tkinter is used for GUI (often included with Python depending on OS distribution).
