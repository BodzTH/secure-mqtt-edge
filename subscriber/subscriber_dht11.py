"""
subscriber_dht11.py
====================
IoT Security Project — DHT11 Subscriber
Receives AES-128-CBC encrypted temperature/humidity from ESP32
via Mosquitto MQTT broker, verifies HMAC-SHA256, and displays
live data in a Tkinter dashboard.

Packet format: HMAC(32) | IV(16) | Ciphertext(N)
HMAC is computed over: IV + Ciphertext  (matches ESP32 sender logic)

On presentation day:
    Change MQTT_BROKER from "127.0.0.1" to "192.168.10.20"
"""

import tkinter as tk
from tkinter import font as tkfont
import threading
import hashlib
import hmac
import time
from datetime import datetime

# ── Crypto ──────────────────────────────────────────────────────────────────
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ── MQTT ────────────────────────────────────────────────────────────────────
import paho.mqtt.client as mqtt

# ════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION  (edit only these lines for deployment)
# ════════════════════════════════════════════════════════════════════════════
MQTT_BROKER = "127.0.0.1"          # ← change to "192.168.10.20" on demo day
MQTT_PORT   = 1883
MQTT_TOPIC  = "esp32/dht11/encrypted"

AES_KEY  = bytes([0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11])
HMAC_KEY = b"ESP32_SECRET_HMAC_KEY"

HMAC_LEN = 32   # SHA-256 digest
IV_LEN   = 16   # AES block size
# ════════════════════════════════════════════════════════════════════════════


# ── Colour palette ───────────────────────────────────────────────────────────
BG        = "#0d1117"
PANEL     = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#58a6ff"
GREEN     = "#3fb950"
YELLOW    = "#d29922"
RED       = "#f85149"
TXT_PRI   = "#e6edf3"
TXT_SEC   = "#8b949e"
TEMP_CLR  = "#ff7b72"
HUM_CLR   = "#79c0ff"


def decrypt_and_verify(raw: bytes):
    """
    Returns (temperature_str, humidity_str) or raises on failure.
    Packet layout:  HMAC[0:32]  |  IV[32:48]  |  Ciphertext[48:]
    HMAC covers:    Ciphertext ONLY  ← Encrypt-then-MAC over ciphertext
    Decryption is performed ONLY if HMAC verification passes.
    """
    if len(raw) < HMAC_LEN + IV_LEN:
        raise ValueError(f"Packet too short: {len(raw)} bytes")

    received_hmac = raw[:HMAC_LEN]
    iv            = raw[HMAC_LEN : HMAC_LEN + IV_LEN]
    ciphertext    = raw[HMAC_LEN + IV_LEN:]

    # ── Verify HMAC over ciphertext BEFORE decrypting ────────────────────────
    expected_hmac = hmac.new(HMAC_KEY, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification FAILED — decryption aborted")

    # ── Decrypt only if HMAC passed ──────────────────────────────────────────
    cipher    = AES.new(AES_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")

    # Expected format: "T:24.50,H:61.20"
    parts = {}
    for token in plaintext.split(","):
        if ":" in token:
            k, v = token.split(":", 1)
            parts[k.strip()] = v.strip()

    temp = parts.get("T", "N/A")
    hum  = parts.get("H", "N/A")
    return temp, hum


class DHT11Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT Security — DHT11 Live Dashboard")
        self.configure(bg=BG)
        self.resizable(False, False)

        self._temp      = "--.-"
        self._hum       = "--.-"
        self._status    = "Connecting…"
        self._status_clr = YELLOW
        self._last_msg  = "—"
        self._msg_count = 0
        self._hmac_ok   = 0
        self._hmac_fail = 0

        self._build_ui()
        self._start_mqtt()

    # ── UI ───────────────────────────────────────────────────────────────────
    def _build_ui(self):
        PAD = 16

        # ── Header ───────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=PANEL, pady=14)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔒  IoT Security Project",
                 bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=PAD)
        self._status_lbl = tk.Label(hdr, text="● Connecting",
                                    bg=PANEL, fg=YELLOW,
                                    font=("Segoe UI", 10))
        self._status_lbl.pack(side="right", padx=PAD)

        # ── Sensor cards row ─────────────────────────────────────────────────
        row = tk.Frame(self, bg=BG, padx=PAD, pady=PAD)
        row.pack(fill="x")

        self._temp_card = self._make_card(
            row, "🌡  Temperature", "--.-", "°C", TEMP_CLR)
        self._temp_card.pack(side="left", expand=True, fill="both", padx=(0, 8))

        self._hum_card = self._make_card(
            row, "💧  Humidity", "--.-", "%", HUM_CLR)
        self._hum_card.pack(side="left", expand=True, fill="both", padx=(8, 0))

        # ── Security stats panel ─────────────────────────────────────────────
        sec = tk.LabelFrame(self, text="  Security Layer  ",
                            bg=PANEL, fg=ACCENT,
                            font=("Segoe UI", 9, "bold"),
                            bd=1, relief="solid",
                            labelanchor="n",
                            padx=14, pady=10)
        sec.pack(fill="x", padx=PAD, pady=(0, PAD))

        self._stat_vars = {}
        stats = [
            ("Algorithm",      "AES-128-CBC + HMAC-SHA256"),
            ("Topic",          MQTT_TOPIC),
            ("Broker",         f"{MQTT_BROKER}:{MQTT_PORT}"),
            ("Messages recv",  "0"),
            ("HMAC ✔",         "0"),
            ("HMAC ✘",         "0"),
            ("Last update",    "—"),
        ]
        for i, (label, val) in enumerate(stats):
            tk.Label(sec, text=label + ":", bg=PANEL, fg=TXT_SEC,
                     font=("Consolas", 9), anchor="w").grid(
                         row=i, column=0, sticky="w", pady=2)
            var = tk.StringVar(value=val)
            self._stat_vars[label] = var
            tk.Label(sec, textvariable=var, bg=PANEL, fg=TXT_PRI,
                     font=("Consolas", 9), anchor="w").grid(
                         row=i, column=1, sticky="w", padx=(12, 0), pady=2)

        # ── Log box ──────────────────────────────────────────────────────────
        log_frame = tk.Frame(self, bg=BG, padx=PAD, pady=(0, PAD))
        log_frame.pack(fill="both", expand=True)

        tk.Label(log_frame, text="Event Log", bg=BG, fg=TXT_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")

        self._log = tk.Text(log_frame, height=8, bg=PANEL, fg=TXT_PRI,
                            font=("Consolas", 9), relief="flat",
                            insertbackground=TXT_PRI, state="disabled",
                            wrap="word", bd=0, padx=6, pady=4)
        self._log.pack(fill="both", expand=True)
        self._log.tag_config("ok",   foreground=GREEN)
        self._log.tag_config("err",  foreground=RED)
        self._log.tag_config("info", foreground=ACCENT)

    def _make_card(self, parent, title, value, unit, color):
        card = tk.Frame(parent, bg=PANEL, padx=20, pady=16,
                        relief="flat", bd=0)
        tk.Label(card, text=title, bg=PANEL, fg=TXT_SEC,
                 font=("Segoe UI", 10)).pack(anchor="w")
        val_row = tk.Frame(card, bg=PANEL)
        val_row.pack(anchor="w", pady=(6, 0))
        lbl = tk.Label(val_row, text=value, bg=PANEL, fg=color,
                       font=("Segoe UI", 42, "bold"))
        lbl.pack(side="left")
        tk.Label(val_row, text=unit, bg=PANEL, fg=color,
                 font=("Segoe UI", 16)).pack(side="left", anchor="s", pady=(0, 8))
        return card

    # ── MQTT ─────────────────────────────────────────────────────────────────
    def _start_mqtt(self):
        self._client = mqtt.Client(client_id="dht11_subscriber")
        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message    = self._on_message

        def _connect():
            try:
                self._client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
                self._client.loop_forever()
            except Exception as exc:
                self.after(0, self._set_status, f"Connection error: {exc}", RED)
                self._log_event(f"Connection error: {exc}", "err")

        threading.Thread(target=_connect, daemon=True).start()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            client.subscribe(MQTT_TOPIC)
            self.after(0, self._set_status, "Connected  ●", GREEN)
            self.after(0, self._log_event,
                       f"Connected to {MQTT_BROKER}:{MQTT_PORT}", "info")
            self.after(0, self._log_event,
                       f"Subscribed → {MQTT_TOPIC}", "info")
        else:
            self.after(0, self._set_status, f"Connect failed (rc={rc})", RED)

    def _on_disconnect(self, client, userdata, rc):
        self.after(0, self._set_status, "Disconnected", YELLOW)
        self.after(0, self._log_event, "Broker disconnected", "err")

    def _on_message(self, client, userdata, msg):
        self._msg_count += 1
        try:
            temp, hum = decrypt_and_verify(msg.payload)
            self._hmac_ok += 1
            ts = datetime.now().strftime("%H:%M:%S")
            self.after(0, self._update_display, temp, hum, ts)
            self.after(0, self._log_event,
                       f"[{ts}] T={temp}°C  H={hum}%  ✔ HMAC OK", "ok")
        except Exception as exc:
            self._hmac_fail += 1
            ts = datetime.now().strftime("%H:%M:%S")
            self.after(0, self._log_event,
                       f"[{ts}] ✘ {exc}", "err")
            self.after(0, self._refresh_stats, ts)

    # ── Display helpers ──────────────────────────────────────────────────────
    def _update_display(self, temp, hum, ts):
        # Rebuild cards with new values
        for widget in self._temp_card.winfo_children():
            widget.destroy()
        for widget in self._hum_card.winfo_children():
            widget.destroy()

        tk.Label(self._temp_card, text="🌡  Temperature",
                 bg=PANEL, fg=TXT_SEC, font=("Segoe UI", 10)).pack(anchor="w")
        row = tk.Frame(self._temp_card, bg=PANEL)
        row.pack(anchor="w", pady=(6, 0))
        tk.Label(row, text=temp, bg=PANEL, fg=TEMP_CLR,
                 font=("Segoe UI", 42, "bold")).pack(side="left")
        tk.Label(row, text="°C", bg=PANEL, fg=TEMP_CLR,
                 font=("Segoe UI", 16)).pack(side="left", anchor="s", pady=(0, 8))

        tk.Label(self._hum_card, text="💧  Humidity",
                 bg=PANEL, fg=TXT_SEC, font=("Segoe UI", 10)).pack(anchor="w")
        row2 = tk.Frame(self._hum_card, bg=PANEL)
        row2.pack(anchor="w", pady=(6, 0))
        tk.Label(row2, text=hum, bg=PANEL, fg=HUM_CLR,
                 font=("Segoe UI", 42, "bold")).pack(side="left")
        tk.Label(row2, text="%", bg=PANEL, fg=HUM_CLR,
                 font=("Segoe UI", 16)).pack(side="left", anchor="s", pady=(0, 8))

        self._refresh_stats(ts)

    def _refresh_stats(self, ts):
        self._stat_vars["Messages recv"].set(str(self._msg_count))
        self._stat_vars["HMAC ✔"].set(str(self._hmac_ok))
        self._stat_vars["HMAC ✘"].set(str(self._hmac_fail))
        self._stat_vars["Last update"].set(ts)

    def _set_status(self, text, color):
        self._status_lbl.config(text=f"● {text}", fg=color)

    def _log_event(self, text, tag="info"):
        self._log.config(state="normal")
        self._log.insert("end", text + "\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")


if __name__ == "__main__":
    app = DHT11Dashboard()
    app.mainloop()
