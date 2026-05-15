/*******************************************************
   ESP32-CAM SECURE MQTT IMAGE TRANSMISSION
   ------------------------------------------------
   Features:
   - Request-based image capture
   - AES128-CBC encryption
   - HMAC-SHA256 integrity/authentication
   - MQTT publisher/subscriber (ArduinoMqttClient)
   - Binary packet transmission

   Packet Structure:
   ------------------------------------------------
   [32 bytes HMAC][16 bytes IV][Encrypted Image]

   Workflow:
   ------------------------------------------------
   Broker sends:
       Topic: esp32cam/request
       Message: capture

   ESP32:
       Capture image
       Generate HMAC-SHA256
       AES128 encrypt image
       Publish secure packet

   Output Topic:
       esp32cam/encrypted_image
********************************************************/

#include "esp_camera.h"
#include <WiFi.h>
#include <ArduinoMqttClient.h> // Official Arduino Library

#include "mbedtls/aes.h"
#include "mbedtls/md.h"

#include <esp_system.h>

#include "esp32-secrets.h"
// =====================================================
// WIFI SETTINGS
// =====================================================

const char* ssid = SECRET_SSID;
const char* password = SECRET_PASS;

// =====================================================
// MQTT SETTINGS
// =====================================================

const char* mqtt_server = SECRET_IP;
const int mqtt_port = 1883;

const char* request_topic = "esp32cam/request";
const char* image_topic   = "esp32cam/encrypted_image";

// =====================================================
// AES + HMAC KEYS
// =====================================================

// AES128 key (16 bytes)
const unsigned char aes_key[16] = SECRET_AES_KEY;

// HMAC key
const unsigned char hmac_key[] = SECRET_HMAC_KEY;

// =====================================================
// FLASH LED
// =====================================================

#define FLASH_LED_PIN 4

// =====================================================
// CAMERA PINS (AI THINKER)
// =====================================================

#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27

#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5

#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

// =====================================================

WiFiClient espClient;
MqttClient mqttClient(espClient);

// =====================================================
// WIFI CONNECTION
// =====================================================

void connectWiFi() {

  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("WiFi connected");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

// =====================================================
// MQTT CONNECTION
// =====================================================

void connectMQTT() {

  while (!mqttClient.connected()) {

    Serial.print("Connecting to MQTT...");

    String clientID = "ESP32CAM-";
    clientID += String(random(0xffff), HEX);
    
    mqttClient.setId(clientID);

    if (mqttClient.connect(mqtt_server, mqtt_port)) {

      Serial.println("connected");

      mqttClient.subscribe(request_topic);

      Serial.println("Subscribed to request topic");

    } else {

      Serial.print("failed, error code = ");
      Serial.println(mqttClient.connectError());

      delay(2000);
    }
  }
}

// =====================================================
// CAMERA SETUP
// =====================================================

void setupCamera() {

  camera_config_t config;

  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;

  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;

  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;

  config.pin_sccb_sda = SIOD_GPIO_NUM;
  config.pin_sccb_scl = SIOC_GPIO_NUM;

  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;

  config.xclk_freq_hz = 20000000;

  config.pixel_format = PIXFORMAT_JPEG;

  // Lower size for memory safety
  config.frame_size = FRAMESIZE_QVGA;

  config.jpeg_quality = 20;

  config.fb_count = 1;

  esp_err_t err = esp_camera_init(&config);

  if (err != ESP_OK) {

    Serial.printf("Camera init failed: 0x%x\n", err);
    return;
  }

  Serial.println("Camera initialized");
}

// =====================================================
// GENERATE RANDOM IV
// =====================================================

void generateIV(unsigned char* iv) {
  esp_fill_random(iv, 16);
}

// =====================================================
// AES128 CBC ENCRYPTION
// =====================================================

bool encryptAES(
  uint8_t* input,
  size_t input_len,
  unsigned char* iv,
  uint8_t** encrypted_output,
  size_t* encrypted_len
) {

  size_t padded_len = ((input_len / 16) + 1) * 16;

  *encrypted_len = padded_len;

  *encrypted_output = (uint8_t*) malloc(padded_len);

  if (!(*encrypted_output)) {
    Serial.println("Encryption malloc failed");
    return false;
  }

  memset(*encrypted_output, 0, padded_len);
  memcpy(*encrypted_output, input, input_len);

  // PKCS7 Padding
  uint8_t pad = padded_len - input_len;

  for (size_t i = input_len; i < padded_len; i++) {
    (*encrypted_output)[i] = pad;
  }

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  if (mbedtls_aes_setkey_enc(&aes, aes_key, 128) != 0) {
    Serial.println("AES key setup failed");
    mbedtls_aes_free(&aes);
    return false;
  }

  unsigned char iv_copy[16];
  memcpy(iv_copy, iv, 16);

  if (mbedtls_aes_crypt_cbc(
        &aes,
        MBEDTLS_AES_ENCRYPT,
        padded_len,
        iv_copy,
        *encrypted_output,
        *encrypted_output
      ) != 0) {

    Serial.println("AES encryption failed");
    mbedtls_aes_free(&aes);
    return false;
  }

  mbedtls_aes_free(&aes);
  return true;
}

// =====================================================
// HMAC-SHA256
// =====================================================

bool generateHMAC(
  uint8_t* data,
  size_t data_len,
  unsigned char* output_hash
) {

  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (!md_info) {
    Serial.println("SHA256 info failed");
    return false;
  }

  if (mbedtls_md_hmac(
        md_info,
        hmac_key,
        strlen((char*)hmac_key),
        data,
        data_len,
        output_hash
      ) != 0) {

    Serial.println("HMAC generation failed");
    return false;
  }

  return true;
}

// =====================================================
// CAPTURE + ENCRYPT + SEND
// =====================================================

void captureAndSendSecureImage() {

  Serial.println("Capturing image...");

  digitalWrite(FLASH_LED_PIN, HIGH);
  delay(100);

  camera_fb_t * fb = esp_camera_fb_get();

  digitalWrite(FLASH_LED_PIN, LOW);

  if (!fb) {

    Serial.println("Capture failed");
    return;
  }

  Serial.printf("Image size: %d bytes\n", fb->len);

  // =================================================
  // STEP 1 -> GENERATE RANDOM IV
  // =================================================

  unsigned char iv[16];

  generateIV(iv);

  // =================================================
  // STEP 2 -> AES ENCRYPT IMAGE
  // =================================================

  uint8_t* encrypted_data = NULL;

  size_t encrypted_len = 0;

  if (!encryptAES(
        fb->buf,
        fb->len,
        iv,
        &encrypted_data,
        &encrypted_len
      )) {

    Serial.println("Encryption failed");

    esp_camera_fb_return(fb);

    return;
  }

  Serial.println("Image encrypted");

  // =================================================
  // STEP 3 -> HMAC OVER CIPHERTEXT
  // =================================================

  unsigned char hmac_output[32];

  if (!generateHMAC(
        encrypted_data,
        encrypted_len,
        hmac_output
      )) {

    Serial.println("HMAC generation failed");

    free(encrypted_data);

    esp_camera_fb_return(fb);

    return;
  }

  Serial.println("HMAC generated over ciphertext");

  // =================================================
  // STEP 4 -> CREATE FINAL PACKET
  // =================================================

  size_t packet_size =
    32 + 16 + encrypted_len;

  uint8_t* final_packet =
    (uint8_t*) malloc(packet_size);

  if (!final_packet) {

    Serial.println("Packet malloc failed");

    free(encrypted_data);

    esp_camera_fb_return(fb);

    return;
  }

  // =================================================
  // PACKET STRUCTURE
  // [32B HMAC][16B IV][CIPHERTEXT]
  // =================================================

  memcpy(final_packet,
         hmac_output,
         32);

  memcpy(final_packet + 32,
         iv,
         16);

  memcpy(final_packet + 48,
         encrypted_data,
         encrypted_len);

  // =================================================
  // STEP 5 -> MQTT PUBLISH
  // =================================================

  mqttClient.beginMessage(
    image_topic,
    (unsigned long)packet_size,
    false,
    0,
    false
  );

  mqttClient.write(
    final_packet,
    packet_size
  );

  int success =
    mqttClient.endMessage();

  if (success) {

    Serial.println(
      "Encrypted image published successfully"
    );

  } else {

    Serial.println(
      "MQTT publish failed"
    );
  }

  // =================================================
  // CLEANUP
  // =================================================

  free(encrypted_data);

  free(final_packet);

  esp_camera_fb_return(fb);
}
// =====================================================
// MQTT CALLBACK (ArduinoMqttClient style)
// =====================================================

void onMqttMessage(int messageSize) {

  // Read the topic of the incoming message
  String topic = mqttClient.messageTopic();
  
  // Read the payload
  String message = "";
  while (mqttClient.available()) {
    message += (char)mqttClient.read();
  }

  Serial.print("Message received on topic [");
  Serial.print(topic);
  Serial.print("]: ");
  Serial.println(message);

  if (message == "capture") {
    Serial.println("Capture request received");
    captureAndSendSecureImage();
  }
}

// =====================================================
// SETUP
// =====================================================

void setup() {

  Serial.begin(115200);
  delay(2000);

  pinMode(FLASH_LED_PIN, OUTPUT);
  digitalWrite(FLASH_LED_PIN, LOW);

  if (psramFound()) {
    Serial.println("PSRAM found");
  } else {
    Serial.println("PSRAM NOT found");
  }

  setupCamera();

  connectWiFi();

  // Set up the message receive callback
  mqttClient.onMessage(onMqttMessage);
  
  // Ensure we allocate enough Tx buffer size for the large packet headers. 
  // We set it to a moderately high size. The actual payload gets streamed.
  mqttClient.setTxPayloadSize(60000); 

  connectMQTT();
}

// =====================================================
// LOOP
// =====================================================

void loop() {

  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    connectMQTT();
  }

  // Poll handles incoming messages and keep-alives
  mqttClient.poll();
}
