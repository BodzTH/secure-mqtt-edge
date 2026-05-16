# Publisher (ESP32)

This folder contains the **ESP32-side publishers** (Arduino/C++) that generate data, encrypt it, authenticate it, and publish it over MQTT.

## Subprojects

- `dht11/` — ESP32 + DHT11 temperature/humidity secure publisher  
  Publishes encrypted telemetry periodically.

- `cam/` — ESP32-CAM secure image publisher  
  Waits for a capture request via MQTT, captures a frame, encrypts/authenticates it, then publishes it.

## Shared packet format

All publishers send messages in this binary format:

`HMAC(32) | IV(16) | CIPHERTEXT(N)`

Where:
- **IV** is random 16 bytes per message
- **Ciphertext** is AES-128-CBC with PKCS7 padding
- **HMAC** is HMAC-SHA256 computed over **ciphertext only** (Encrypt-then-MAC)

## Configuration

Both sketches include `esp32-secrets.h` which should define:
- Wi‑Fi SSID/password
- MQTT broker IP/hostname
- AES key (16 bytes)
- HMAC key

You typically place `esp32-secrets.h` in the same directory as the `.ino` you are building.

See each subfolder README for details.
