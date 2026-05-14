"""
============================================================
  subscriber_cam.py — ESP32-CAM Secure Image Subscriber
  IoT Security Project

  Topic (receive): esp32cam/encrypted_image
  Topic (send)   : esp32cam/request  → publishes "capture"

  Packet format (confirmed from cam.ino):
    [0..31]  HMAC-SHA256   32 bytes  (over plaintext image)
    [32..47] IV            16 bytes  (AES-CBC nonce)
    [48..]   ciphertext    N bytes   (AES-128-CBC, PKCS7 padded)

  IMPORTANT — HMAC is computed over the PLAINTEXT image,
  then the image is encrypted. So we must:
    1. Decrypt first
    2. Verify HMAC after decryption

  Install:
    pip install paho-mqtt cryptography pillow
============================================================
"""

import hmac
import hashlib
import io
import queue
import tkinter as tk
from tkinter import font as tkfont
from datetime import datetime

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk

# ══════════════════════════════════════════════════════════════
#  CONFIGURATION — edit these to match your setup
# ══════════════════════════════════════════════════════════════

MQTT_BROKER    = "127.0.0.1"   # Change to broker IP (192.168.10.20 on demo day)
MQTT_PORT      = 1883
IMAGE_TOPIC    = "esp32cam/encrypted_image"   # ESP32-CAM publishes here
REQUEST_TOPIC  = "esp32cam/request"           # We publish "capture" here
CLIENT_ID      = "subscriber_cam"

# Keys MUST match cam.ino exactly
AES_KEY = bytes([
    0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11
])
HMAC_KEY = b"ESP32_SECRET_HMAC_KEY"

# ── Thread-safe queue: MQTT thread → GUI thread ───────────────
frame_queue = queue.Queue()


# ══════════════════════════════════════════════════════════════
#  CRYPTO
# ══════════════════════════════════════════════════════════════

def decrypt_image(ciphertext: bytes, iv: bytes) -> bytes | None:
    """
    AES-128-CBC decrypt + PKCS7 unpad.
    ciphertext length MUST be a multiple of 16.
    Returns raw image bytes or None on failure.
    """
    # Safety check — ciphertext must be a non-zero multiple of AES block size
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        print(f"  [CRYPTO] Bad ciphertext length: {len(ciphertext)}"
              f" (must be nonzero multiple of 16)")
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


def verify_hmac(plaintext_image: bytes, received_hmac: bytes) -> bool:
    """
    HMAC-SHA256 is computed over the PLAINTEXT image (before encryption).
    This matches how cam.ino generates it: generateHMAC(fb->buf, fb->len).
    Uses compare_digest to prevent timing attacks.
    """
    expected = hmac.new(HMAC_KEY, plaintext_image, hashlib.sha256).digest()
    return hmac.compare_digest(expected, received_hmac)


# ══════════════════════════════════════════════════════════════
#  MQTT CALLBACKS
# ══════════════════════════════════════════════════════════════

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[MQTT] ✓ Connected to {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe(IMAGE_TOPIC, qos=1)
        print(f"[MQTT] Subscribed → {IMAGE_TOPIC}")
        # Signal GUI to update status
        frame_queue.put(("status", "✓ Connected to broker. Ready to capture."))
    else:
        msg = f"✗ Connection failed (code={reason_code})"
        print(f"[MQTT] {msg}")
        frame_queue.put(("status", msg))


def on_disconnect(client, userdata, flags, reason_code, properties):
    if reason_code != 0:
        print("[MQTT] Disconnected unexpectedly — reconnecting...")
        frame_queue.put(("status", "⚠ Disconnected — reconnecting..."))


def on_message(client, userdata, msg):
    """Called by paho in its background thread when a message arrives."""
    payload   = bytes(msg.payload)
    total_len = len(payload)

    print(f"\n[IMG] Received {total_len} bytes on {msg.topic}")
    frame_queue.put(("status", f"📥 Received {total_len} bytes — decrypting..."))

    # ── 1. Minimum length check ───────────────────────────────
    # 32 (HMAC) + 16 (IV) + 16 (min 1 AES block) = 64
    if total_len < 64:
        msg_txt = f"✗ Packet too short ({total_len} bytes)"
        print(f"  [ERR] {msg_txt}")
        frame_queue.put(("status", msg_txt))
        return

    # ── 2. Parse packet: HMAC(32) | IV(16) | ciphertext(N) ───
    received_hmac = payload[0:32]
    iv            = payload[32:48]
    ciphertext    = payload[48:]

    print(f"  HMAC      : {received_hmac.hex()[:16]}...")
    print(f"  IV        : {iv.hex()}")
    print(f"  CT length : {len(ciphertext)} bytes")

    # ── 3. Decrypt ────────────────────────────────────────────
    image_bytes = decrypt_image(ciphertext, iv)
    if image_bytes is None:
        frame_queue.put(("status", "✗ Decryption failed — check AES key"))
        return
    print(f"  [CRYPTO] ✓ Decrypted {len(ciphertext)} → {len(image_bytes)} bytes")

    # ── 4. Verify HMAC (over plaintext image, after decryption) ─
    if not verify_hmac(image_bytes, received_hmac):
        msg_txt = "✗ HMAC verification failed — image may be tampered!"
        print(f"  [SECURITY] ❌ {msg_txt}")
        frame_queue.put(("status", msg_txt))
        return
    print("  [SECURITY] ✓ HMAC-SHA256 verified")

    # ── 5. Decode JPEG and send to GUI thread ─────────────────
    try:
        img = Image.open(io.BytesIO(image_bytes))
        ts  = datetime.now().strftime("%H:%M:%S")
        print(f"  [IMG] ✓ Image decoded ({img.size[0]}x{img.size[1]} px) at {ts}")
        frame_queue.put(("image", img))
        frame_queue.put(("status",
            f"✓ Image received & verified  {img.size[0]}×{img.size[1]}px  [{ts}]"))
    except Exception as e:
        msg_txt = f"✗ Image decode error: {e}"
        print(f"  [ERR] {msg_txt}")
        frame_queue.put(("status", msg_txt))


# ══════════════════════════════════════════════════════════════
#  TKINTER GUI
# ══════════════════════════════════════════════════════════════

class CamSubscriberApp:
    def __init__(self, root, mqtt_client):
        self.root       = root
        self.mqtt_client = mqtt_client
        self.root.title("ESP32-CAM Secure Subscriber")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, True)

        title_font  = tkfont.Font(family="Consolas", size=14, weight="bold")
        btn_font    = tkfont.Font(family="Consolas", size=12, weight="bold")
        status_font = tkfont.Font(family="Consolas", size=10)

        # ── Title bar ─────────────────────────────────────────
        tk.Label(
            root, text="📷  ESP32-CAM Secure Viewer",
            bg="#1e1e2e", fg="#cdd6f4",
            font=title_font, pady=10
        ).pack(fill="x")

        # ── Status label ──────────────────────────────────────
        self.status_var = tk.StringVar(value="⏳ Connecting to broker...")
        tk.Label(
            root, textvariable=self.status_var,
            bg="#313244", fg="#a6e3a1",
            font=status_font, pady=6, padx=10,
            anchor="w", relief="flat"
        ).pack(fill="x", padx=10, pady=(0, 6))

        # ── Image display area ────────────────────────────────
        self.image_frame = tk.Frame(root, bg="#181825", width=640, height=480)
        self.image_frame.pack(padx=10, pady=6)
        self.image_frame.pack_propagate(False)

        self.image_label = tk.Label(
            self.image_frame,
            text="No image yet\nPress 'Capture' to request one",
            bg="#181825", fg="#585b70",
            font=tkfont.Font(family="Consolas", size=11)
        )
        self.image_label.pack(expand=True)

        # ── Capture button ────────────────────────────────────
        self.btn = tk.Button(
            root,
            text="📸  Capture Image",
            command=self.request_capture,
            font=btn_font,
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", padx=20, pady=10,
            cursor="hand2"
        )
        self.btn.pack(pady=10)

        # ── Keyboard shortcut ─────────────────────────────────
        self.root.bind("<c>",      lambda e: self.request_capture())
        self.root.bind("<Return>", lambda e: self.request_capture())
        self.root.bind("<Escape>", lambda e: self.root.destroy())

        # Start polling the queue
        self.poll_queue()

    def request_capture(self):
        """Publishes 'capture' to esp32cam/request topic."""
        result = self.mqtt_client.publish(REQUEST_TOPIC, "capture", qos=1)
        if result.rc == 0:
            ts = datetime.now().strftime("%H:%M:%S")
            self.status_var.set(f"📤 Capture request sent [{ts}] — waiting for image...")
            print(f"[GUI] Capture request published to '{REQUEST_TOPIC}'")
        else:
            self.status_var.set("✗ Failed to send capture request — check connection")
            print(f"[GUI] Publish failed, rc={result.rc}")

    def poll_queue(self):
        """
        Checks the thread-safe queue for messages from the MQTT thread.
        Runs every 50ms on the main GUI thread — never blocks.
        """
        try:
            while not frame_queue.empty():
                item = frame_queue.get_nowait()
                kind, data = item

                if kind == "image":
                    self._display_image(data)
                elif kind == "status":
                    self.status_var.set(data)

        except queue.Empty:
            pass

        # Schedule next poll in 50ms
        self.root.after(50, self.poll_queue)

    def _display_image(self, pil_img: Image.Image):
        """Resizes image to fit the panel and displays it."""
        # Fit inside the 640×480 frame while keeping aspect ratio
        pil_img.thumbnail((630, 470), Image.LANCZOS)
        tk_img = ImageTk.PhotoImage(pil_img)

        self.image_label.config(image=tk_img, text="", bg="#181825")
        self.image_label.image = tk_img   # Keep reference — prevents garbage collection


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print("=" * 54)
    print("  ESP32-CAM Secure Subscriber")
    print(f"  Broker  : {MQTT_BROKER}:{MQTT_PORT}")
    print(f"  Listen  : {IMAGE_TOPIC}")
    print(f"  Request : {REQUEST_TOPIC}")
    print(f"  AES key : {AES_KEY.hex()}")
    print("=" * 54 + "\n")

    # ── Setup MQTT client ─────────────────────────────────────
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id=CLIENT_ID)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    print(f"[MQTT] Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    except Exception as e:
        print(f"[FATAL] Cannot connect to broker: {e}")
        print("  → Make sure Mosquitto is running and you're on the right Wi-Fi.")
        return

    # Run MQTT in background thread — does NOT block the GUI
    client.loop_start()

    # ── Launch Tkinter GUI (must be on main thread) ───────────
    root = tk.Tk()
    app  = CamSubscriberApp(root, client)

    def on_close():
        client.loop_stop()
        client.disconnect()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
