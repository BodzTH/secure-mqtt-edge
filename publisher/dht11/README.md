# ESP32 + DHT11 Secure Publisher

Secure temperature/humidity telemetry publisher using ESP32 + DHT11 over MQTT.

## What it does

Every ~5 seconds the ESP32:
1. Reads temperature & humidity from a DHT11 sensor
2. Formats plaintext as:
   - `T:<temp>,H:<humidity>` (example: `T:27.50,H:61.00`)
3. Generates a random IV (16 bytes)
4. Encrypts with **AES-128-CBC** (PKCS7 padding)
5. Computes **HMAC-SHA256 over ciphertext only**
6. Publishes packet: `HMAC(32) | IV(16) | CIPHERTEXT(N)`

## MQTT topic

- Publish topic: `esp32/dht11/encrypted`

## Dependencies

- Arduino core for ESP32
- `ArduinoMqttClient` for MQTT
- `DHT` library for DHT11 sensor access
- mbedTLS (AES + HMAC)

## Hardware

- ESP32
- DHT11 sensor wired to:
  - Data pin: GPIO 14 (as defined in the sketch)
  - VCC / GND as appropriate

## Secrets / configuration (`esp32-secrets.h`)

This sketch expects an `esp32-secrets.h` containing:
- `SECRET_SSID`
- `SECRET_PASS`
- `SECRET_IP` (MQTT broker IP/hostname)
- `SECRET_AES_KEY` (16 bytes)
- `SECRET_HMAC_KEY`

## Subscriber

Use the Python dashboard:
```bash
python subscriber/subscriber_dht11.py
```

It verifies the HMAC first, decrypts the payload, parses `T:` and `H:`, and updates a Tkinter UI.
