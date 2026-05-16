"""
subscriber_cam.py
==================
IoT Security Project — ESP32-CAM Subscriber
Receives AES-128-CBC encrypted JPEG image from ESP32-CAM
via Mosquitto MQTT broker, verifies HMAC-SHA256, and displays
the photo in a Tkinter GUI with a Capture request button.

Packet format: HMAC(32) | IV(16) | Ciphertext(N)
HMAC is computed over: Ciphertext ONLY  (Encrypt-then-MAC)

On presentation day:
    Change MQTT_BROKER from "127.0.0.1" to "192.168.10.20"
"""

import tkinter as tk
from tkinter import messagebox
import threading
import hashlib
import hmac
import io
from datetime import datetime

# ── Crypto (Using the industry-standard 'cryptography' library) ─────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ── MQTT ────────────────────────────────────────────────────────────────────
import paho.mqtt.client as mqtt

# ── Image ───────────────────────────────────────────────────────────────────
from PIL import Image, ImageTk

# ════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION  (edit only these lines for deployment)
# ════════════════════════════════════════════════════════════════════════════
MQTT_BROKER   = "127.0.0.1"            # ← change to "192.168.10.20" on demo day
MQTT_PORT     = 1883
TOPIC_IMAGE   = "esp32cam/encrypted_image"
TOPIC_REQUEST = "esp32cam/request"      # publishes "capture" here

AES_KEY  = bytes([0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11])
HMAC_KEY = b"ESP32_SECRET_HMAC_KEY"

HMAC_LEN     = 32    # SHA-256 digest
IV_LEN       = 16    # AES block size
PREVIEW_SIZE = (480, 360)   # canvas preview size (px)
# ════════════════════════════════════════════════════════════════════════════


# ── Colour palette ───────────────────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#58a6ff"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
RED      = "#f85149"
TXT_PRI  = "#e6edf3"
TXT_SEC  = "#8b949e"
BTN_NORM = "#238636"
BTN_HOV  = "#2ea043"


def decrypt_and_verify(raw: bytes) -> bytes:
    """
    Returns decrypted JPEG bytes or raises on failure.
    Packet layout:  HMAC[0:32]  |  IV[32:48]  |  Ciphertext[48:]
    HMAC covers:    Ciphertext ONLY  ← Encrypt-then-MAC over ciphertext
    Decryption is performed ONLY if HMAC verification passes.
    """
    if len(raw) < HMAC_LEN + IV_LEN:
        raise ValueError(f"Packet too short: {len(raw)} bytes")

    received_hmac = raw[:HMAC_LEN]
    iv            = raw[HMAC_LEN : HMAC_LEN + IV_LEN]
    ciphertext    = raw[HMAC_LEN + IV_LEN:]

    # ── Verify HMAC over ciphertext BEFORE decrypting (Encrypt-then-MAC) ─────
    expected_hmac = hmac.new(HMAC_KEY, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification FAILED — decryption aborted")

    # ── Decrypt only if HMAC passed ──────────────────────────────────────────
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # ── Unpad the decrypted data (PKCS7, 128-bit block size for AES) ─────────
    unpadder = padding.PKCS7(128).unpadder()
    jpeg_raw = unpadder.update(padded_data) + unpadder.finalize()
    
    return jpeg_raw


class CamSubscriber(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT Security — ESP32-CAM Viewer")
        self.configure(bg=BG)
        self.resizable(False, False)

        self._photo_ref  = None   # keep PhotoImage alive
        self._msg_count  = 0
        self._hmac_ok    = 0
        self._hmac_fail  = 0
        self._connected  = False
        self._last_jpeg  = None   # raw bytes of last image (for save)

        self._build_ui()
        self._start_mqtt()

    # ── UI ───────────────────────────────────────────────────────────────────
    def _build_ui(self):
        PAD = 16

        # ── Header ───────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=PANEL, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔒  IoT Security Project — CAM Subscriber",
                 bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=PAD)
        self._status_lbl = tk.Label(hdr, text="● Connecting",
                                    bg=PANEL, fg=YELLOW,
                                    font=("Segoe UI", 10))
        self._status_lbl.pack(side="right", padx=PAD)

        # ── Main body (image + sidebar) ──────────────────────────────────────
        body = tk.Frame(self, bg=BG, padx=PAD, pady=PAD)
        body.pack(fill="both", expand=True)

        # Image canvas
        self._canvas = tk.Canvas(
            body,
            width=PREVIEW_SIZE[0], height=PREVIEW_SIZE[1],
            bg="#0a0a0a", highlightthickness=1,
            highlightbackground=BORDER)
        self._canvas.pack(side="left")
        self._canvas.create_text(
            PREVIEW_SIZE[0] // 2, PREVIEW_SIZE[1] // 2,
            text="No image received yet",
            fill=TXT_SEC, font=("Segoe UI", 11), tags="placeholder")

        # Sidebar
        sidebar = tk.Frame(body, bg=BG, padx=PAD)
        sidebar.pack(side="left", fill="y")

        # Capture button
        self._cap_btn = tk.Button(
            sidebar,
            text="📷  Capture",
            bg=BTN_NORM, fg="white",
            activebackground=BTN_HOV, activeforeground="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat", padx=20, pady=10, cursor="hand2",
            command=self._request_capture)
        self._cap_btn.pack(fill="x", pady=(0, 12))

        # Security info
        sec = tk.LabelFrame(sidebar, text="  Security  ",
                            bg=PANEL, fg=ACCENT,
                            font=("Segoe UI", 9, "bold"),
                            bd=1, relief="solid",
                            labelanchor="n",
                            padx=10, pady=8)
        sec.pack(fill="x", pady=(0, 12))

        self._stat_vars = {}
        stats = [
            ("Algorithm",     "AES-128-CBC"),
            ("Auth",          "HMAC-SHA256"),
            ("Broker",        f"{MQTT_BROKER}:{MQTT_PORT}"),
            ("Image topic",   TOPIC_IMAGE),
            ("Req topic",     TOPIC_REQUEST),
            ("Images recv",   "0"),
            ("HMAC ✔",        "0"),
            ("HMAC ✘",        "0"),
            ("Last capture",  "—"),
        ]
        for i, (label, val) in enumerate(stats):
            tk.Label(sec, text=label + ":", bg=PANEL, fg=TXT_SEC,
                     font=("Consolas", 8), anchor="w").grid(
                         row=i, column=0, sticky="w", pady=1)
            var = tk.StringVar(value=val)
            self._stat_vars[label] = var
            tk.Label(sec, textvariable=var, bg=PANEL, fg=TXT_PRI,
                     font=("Consolas", 8), anchor="w").grid(
                         row=i, column=1, sticky="w", padx=(8, 0), pady=1)

        # Timestamp label below canvas
        self._ts_lbl = tk.Label(self, text="",
                                bg=BG, fg=TXT_SEC,
                                font=("Consolas", 9))
        self._ts_lbl.pack(pady=(0, 4))

        # ── Log box ──────────────────────────────────────────────────────────
        log_frame = tk.Frame(self, bg=BG, padx=PAD)
        log_frame.pack(fill="both", expand=True, pady=(0, PAD))

        tk.Label(log_frame, text="Event Log", bg=BG, fg=TXT_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")

        self._log = tk.Text(log_frame, height=6, bg=PANEL, fg=TXT_PRI,
                            font=("Consolas", 9), relief="flat",
                            insertbackground=TXT_PRI, state="disabled",
                            wrap="word", bd=0, padx=6, pady=4)
        self._log.pack(fill="both", expand=True)
        self._log.tag_config("ok",   foreground=GREEN)
        self._log.tag_config("err",  foreground=RED)
        self._log.tag_config("info", foreground=ACCENT)
        self._log.tag_config("warn", foreground=YELLOW)

    # ── MQTT ─────────────────────────────────────────────────────────────────
    def _start_mqtt(self):
        # 1. Initialize Paho MQTT with VERSION2
        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cam_subscriber")
        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message    = self._on_message

        def _connect():
            try:
                self._client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
                self._client.loop_forever()
            except Exception as exc:
                self.after(0, self._set_status, f"Connection error: {exc}", RED)
                self.after(0, self._log_event, f"Connection error: {exc}", "err")

        threading.Thread(target=_connect, daemon=True).start()

    # 2. Add 'properties' to the connect callback signature
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            self._connected = True
            client.subscribe(TOPIC_IMAGE)
            self.after(0, self._set_status, "Connected  ●", GREEN)
            self.after(0, self._log_event,
                       f"Connected to {MQTT_BROKER}:{MQTT_PORT}", "info")
            self.after(0, self._log_event,
                       f"Subscribed → {TOPIC_IMAGE}", "info")
        else:
            self.after(0, self._set_status, f"Connect failed (rc={reason_code})", RED)

    # 3. Add 'disconnect_flags' and 'properties' to the disconnect callback signature
    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        self._connected = False
        self.after(0, self._set_status, "Disconnected", YELLOW)
        self.after(0, self._log_event, "Broker disconnected", "err")

    # 4. Restored the _on_message function that was missing!
    def _on_message(self, client, userdata, msg):
        self._msg_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            jpeg_bytes = decrypt_and_verify(msg.payload)
            self._hmac_ok  += 1
            self._last_jpeg = jpeg_bytes
            self.after(0, self._display_image, jpeg_bytes, ts)
            self.after(0, self._log_event,
                       f"[{ts}] Image received ({len(jpeg_bytes):,} bytes) ✔ HMAC OK", "ok")
        except Exception as exc:
            self._hmac_fail += 1
            self.after(0, self._log_event, f"[{ts}] ✘ {exc}", "err")
            self.after(0, self._refresh_stats, ts)

    # ── Capture request ───────────────────────────────────────────────────────
    def _request_capture(self):
        if not self._connected:
            self._log_event("Not connected — cannot send capture request", "warn")
            return
        try:
            self._client.publish(TOPIC_REQUEST, "capture", qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self._log_event(f"[{ts}] Capture request sent → {TOPIC_REQUEST}", "info")
        except Exception as exc:
            self._log_event(f"Publish error: {exc}", "err")

    # ── Display helpers ───────────────────────────────────────────────────────
    def _display_image(self, jpeg_bytes: bytes, ts: str):
        try:
            img = Image.open(io.BytesIO(jpeg_bytes))
            img.thumbnail(PREVIEW_SIZE, Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)

            self._canvas.delete("all")
            # Centre the thumbnail
            cx = PREVIEW_SIZE[0] // 2
            cy = PREVIEW_SIZE[1] // 2
            self._canvas.create_image(cx, cy, anchor="center", image=photo)
            self._photo_ref = photo  # prevent GC

            self._ts_lbl.config(
                text=f"Last frame: {ts}  |  "
                     f"{img.size[0]}×{img.size[1]} px  |  "
                     f"{len(jpeg_bytes):,} bytes")
        except Exception as exc:
            self._log_event(f"Image render error: {exc}", "err")

        self._refresh_stats(ts)

    def _refresh_stats(self, ts):
        self._stat_vars["Images recv"].set(str(self._msg_count))
        self._stat_vars["HMAC ✔"].set(str(self._hmac_ok))
        self._stat_vars["HMAC ✘"].set(str(self._hmac_fail))
        self._stat_vars["Last capture"].set(ts)

    def _set_status(self, text, color):
        self._status_lbl.config(text=f"● {text}", fg=color)

    def _log_event(self, text, tag="info"):
        self._log.config(state="normal")
        self._log.insert("end", text + "\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")


if __name__ == "__main__":
    app = CamSubscriber()
    app.mainloop()
