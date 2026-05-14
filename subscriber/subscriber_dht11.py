"""
============================================================
  subscriber_dht11.py — DHT11 Secure Temperature Subscriber
  IoT Security Project

  Topic   : esp32/dht11/encrypted
  Security: AES-128-CBC decrypt + HMAC-SHA256 verify

  Packet format:
    [0..31]  HMAC-SHA256  32 bytes  (over plaintext JSON)
    [32..47] IV           16 bytes
    [48..]   ciphertext   N bytes   (AES-128-CBC, PKCS7 padded)

  Plaintext JSON after decryption:
    {"device":"esp32","temp":24.5,"hum":58.3,"unit":"C"}

  Install:
    pip install paho-mqtt cryptography
============================================================
"""

import hmac as hmac_lib
import hashlib
import json
import sys
import tkinter as tk
from tkinter import font as tkfont
from datetime import datetime

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ══════════════════════════════════════════════════════════════
#  CONFIGURATION — edit these to match your setup
# ══════════════════════════════════════════════════════════════

MQTT_BROKER    = "127.0.0.1"      # Change to broker IP
MQTT_PORT      = 1883
DHT_TOPIC      = "esp32/dht11/encrypted"   # ← change if different
CLIENT_ID      = "subscriber_dht11"

AES_KEY = bytes([
    0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11
])
HMAC_KEY = b"ESP32_SECRET_HMAC_KEY"

# Packet offsets
OFF_HMAC = 0
OFF_IV   = 32
OFF_CT   = 48
MIN_LEN  = 49

# Keep last 8 readings for history display
MAX_HISTORY = 8


# ══════════════════════════════════════════════════════════════
#  CRYPTO
# ══════════════════════════════════════════════════════════════

def aes128_cbc_decrypt(ciphertext: bytes, iv: bytes) -> bytes | None:
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        print(f"  [CRYPTO] Bad ciphertext length: {len(ciphertext)}")
        return None
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


def verify_hmac(plaintext: bytes, received_hmac: bytes) -> bool:
    """HMAC is over the plaintext (after decryption)."""
    expected = hmac_lib.new(HMAC_KEY, plaintext, hashlib.sha256).digest()
    return hmac_lib.compare_digest(expected, received_hmac)


# ══════════════════════════════════════════════════════════════
#  TKINTER GUI
# ══════════════════════════════════════════════════════════════

class DHT11App:
    def __init__(self, root):
        self.root = root
        self.root.title("DHT11 Secure Subscriber")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        title_font   = tkfont.Font(family="Consolas", size=14, weight="bold")
        value_font   = tkfont.Font(family="Consolas", size=42, weight="bold")
        label_font   = tkfont.Font(family="Consolas", size=11)
        history_font = tkfont.Font(family="Consolas", size=9)
        status_font  = tkfont.Font(family="Consolas", size=10)

        # ── Title ─────────────────────────────────────────────
        tk.Label(root, text="🌡  DHT11 Secure Monitor",
                 bg="#1e1e2e", fg="#cdd6f4",
                 font=title_font, pady=10).pack(fill="x")

        # ── Status bar ────────────────────────────────────────
        self.status_var = tk.StringVar(value="⏳ Connecting...")
        tk.Label(root, textvariable=self.status_var,
                 bg="#313244", fg="#a6e3a1",
                 font=status_font, pady=5, padx=10,
                 anchor="w").pack(fill="x", padx=10)

        # ── Big reading cards ──────────────────────────────────
        cards = tk.Frame(root, bg="#1e1e2e")
        cards.pack(padx=20, pady=15)

        # Temperature card
        temp_card = tk.Frame(cards, bg="#313244", padx=25, pady=15)
        temp_card.grid(row=0, column=0, padx=10)
        tk.Label(temp_card, text="Temperature",
                 bg="#313244", fg="#89b4fa", font=label_font).pack()
        self.temp_var = tk.StringVar(value="--.-")
        tk.Label(temp_card, textvariable=self.temp_var,
                 bg="#313244", fg="#f38ba8",
                 font=value_font).pack()
        tk.Label(temp_card, text="°C",
                 bg="#313244", fg="#f38ba8", font=label_font).pack()

        # Humidity card
        hum_card = tk.Frame(cards, bg="#313244", padx=25, pady=15)
        hum_card.grid(row=0, column=1, padx=10)
        tk.Label(hum_card, text="Humidity",
                 bg="#313244", fg="#89b4fa", font=label_font).pack()
        self.hum_var = tk.StringVar(value="--.-")
        tk.Label(hum_card, textvariable=self.hum_var,
                 bg="#313244", fg="#89dceb",
                 font=value_font).pack()
        tk.Label(hum_card, text="%",
                 bg="#313244", fg="#89dceb", font=label_font).pack()

        # ── Security badges ───────────────────────────────────
        badge_frame = tk.Frame(root, bg="#1e1e2e")
        badge_frame.pack(pady=5)

        self.hmac_badge = tk.Label(
            badge_frame, text="HMAC ●",
            bg="#1e1e2e", fg="#585b70", font=label_font)
        self.hmac_badge.pack(side="left", padx=8)

        self.aes_badge = tk.Label(
            badge_frame, text="AES-128 ●",
            bg="#1e1e2e", fg="#585b70", font=label_font)
        self.aes_badge.pack(side="left", padx=8)

        self.device_var = tk.StringVar(value="Device: —")
        tk.Label(root, textvariable=self.device_var,
                 bg="#1e1e2e", fg="#6c7086",
                 font=history_font).pack()

        # ── Reading history ───────────────────────────────────
        tk.Label(root, text="Recent Readings",
                 bg="#1e1e2e", fg="#6c7086",
                 font=label_font, pady=4).pack()

        self.history_text = tk.Text(
            root, height=MAX_HISTORY, width=52,
            bg="#181825", fg="#cdd6f4",
            font=history_font, relief="flat",
            state="disabled", padx=8, pady=4
        )
        self.history_text.pack(padx=10, pady=(0, 10))

    def update_reading(self, data: dict, hmac_ok: bool):
        temp   = data.get("temp", "?")
        hum    = data.get("hum",  "?")
        device = data.get("device", "esp32")
        unit   = data.get("unit", "C")
        ts     = datetime.now().strftime("%H:%M:%S")

        self.temp_var.set(str(temp))
        self.hum_var.set(str(hum))
        self.device_var.set(f"Device: {device}")
        self.status_var.set(f"✓ Reading received at {ts}")

        # Security badges — green when passing
        if hmac_ok:
            self.hmac_badge.config(fg="#a6e3a1", text="HMAC ✓")
            self.aes_badge.config(fg="#a6e3a1",  text="AES-128 ✓")
        else:
            self.hmac_badge.config(fg="#f38ba8", text="HMAC ✗")

        # Append to history
        line = f"[{ts}]  {temp}°{unit}  {hum}%  {'✓' if hmac_ok else '✗ TAMPERED'}\n"
        self.history_text.config(state="normal")
        self.history_text.insert("end", line)
        # Keep only last MAX_HISTORY lines
        lines = int(self.history_text.index("end-1c").split(".")[0])
        if lines > MAX_HISTORY:
            self.history_text.delete("1.0", "2.0")
        self.history_text.config(state="disabled")
        self.history_text.see("end")

    def set_status(self, msg: str, color: str = "#a6e3a1"):
        self.status_var.set(msg)


# ── Global GUI reference (set in main) ───────────────────────
app_gui: DHT11App = None


# ══════════════════════════════════════════════════════════════
#  MQTT CALLBACKS
# ══════════════════════════════════════════════════════════════

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[MQTT] ✓ Connected to {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe(DHT_TOPIC, qos=1)
        print(f"[MQTT] Subscribed → {DHT_TOPIC}")
        if app_gui:
            app_gui.set_status(f"✓ Connected — listening on {DHT_TOPIC}")
    else:
        print(f"[MQTT] ✗ Connect failed (code={reason_code})")
        if app_gui:
            app_gui.set_status(f"✗ Connection failed (code={reason_code})")


def on_disconnect(client, userdata, flags, reason_code, properties):
    if reason_code != 0:
        print("[MQTT] Disconnected — reconnecting...")
        if app_gui:
            app_gui.set_status("⚠ Disconnected — reconnecting...")


def on_message(client, userdata, msg):
    raw = bytes(msg.payload)
    print(f"\n[DHT] Received {len(raw)} bytes")

    # ── Length check ──────────────────────────────────────────
    if len(raw) < MIN_LEN:
        print(f"  [ERR] Packet too short ({len(raw)} bytes)")
        if app_gui:
            app_gui.set_status(f"✗ Packet too short ({len(raw)} bytes)")
        return

    # ── Parse packet ──────────────────────────────────────────
    received_hmac = raw[OFF_HMAC : OFF_HMAC + 32]
    iv            = raw[OFF_IV   : OFF_IV   + 16]
    ciphertext    = raw[OFF_CT:]

    # ── Decrypt ───────────────────────────────────────────────
    plaintext = aes128_cbc_decrypt(ciphertext, iv)
    if plaintext is None:
        if app_gui:
            app_gui.set_status("✗ Decryption failed — check AES key")
        return
    print(f"  [CRYPTO] ✓ Decrypted {len(ciphertext)} → {len(plaintext)} bytes")

    # ── Verify HMAC (over plaintext) ──────────────────────────
    hmac_ok = verify_hmac(plaintext, received_hmac)
    if hmac_ok:
        print("  [SECURITY] ✓ HMAC-SHA256 verified")
    else:
        print("  [SECURITY] ❌ HMAC FAILED — data may be tampered!")

    # ── Parse JSON ────────────────────────────────────────────
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"  [ERR] JSON parse error: {e}")
        if app_gui:
            app_gui.set_status(f"✗ JSON parse error: {e}")
        return

    print(f"  Temp={data.get('temp')}°{data.get('unit','C')}  "
          f"Hum={data.get('hum')}%  Device={data.get('device')}")

    # ── Update GUI (safe — runs from MQTT thread via after()) ─
    if app_gui:
        app_gui.root.after(0, lambda: app_gui.update_reading(data, hmac_ok))


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    global app_gui

    print("=" * 54)
    print("  DHT11 Secure Subscriber")
    print(f"  Broker : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"  Topic  : {DHT_TOPIC}")
    print(f"  AES key: {AES_KEY.hex()}")
    print("=" * 54 + "\n")

    # ── MQTT setup ────────────────────────────────────────────
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id=CLIENT_ID)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    print(f"[MQTT] Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    except Exception as e:
        print(f"[FATAL] Cannot connect: {e}")
        return

    client.loop_start()   # Background thread — won't block GUI

    # ── Launch GUI ────────────────────────────────────────────
    root    = tk.Tk()
    app_gui = DHT11App(root)

    def on_close():
        client.loop_stop()
        client.disconnect()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
