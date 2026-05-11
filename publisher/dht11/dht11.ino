/************************************************************
   ESP32 + DHT11 SECURE MQTT PUBLISHER
   ---------------------------------------------------------
   Features:
   - Reads temperature and humidity
   - AES128-CBC encryption
   - HMAC-SHA256 integrity/authentication
   - MQTT secure publishing
   - Hardware accelerated crypto (ESP32)

   Packet Structure:
   ---------------------------------------------------------
   [32 bytes HMAC][16 bytes IV][Encrypted Data]

   Example Plaintext Before Encryption:
   ---------------------------------------------------------
   TEMP:27.50,HUM:61.00

************************************************************/

#define MQTT_MAX_PACKET_SIZE 2048

#include <WiFi.h>
#include <PubSubClient.h>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"

#include <esp_system.h>

#include "DHT.h"

// ========================================================
// WIFI SETTINGS
// ========================================================

const char* ssid = "YOUR_WIFI_NAME";
const char* password = "YOUR_WIFI_PASSWORD";

// ========================================================
// MQTT SETTINGS
// ========================================================

const char* mqtt_server = "192.168.1.100";
const int mqtt_port = 1883;

const char* sensor_topic =
  "esp32/dht11/encrypted";

// ========================================================
// DHT11 SETTINGS
// ========================================================

#define DHTPIN 4
#define DHTTYPE DHT11

DHT dht(DHTPIN, DHTTYPE);

// ========================================================
// AES128 KEY
// ========================================================

const unsigned char aes_key[16] = {

  0x10,0x22,0x33,0x44,
  0x55,0x66,0x77,0x88,
  0x99,0xaa,0xbb,0xcc,
  0xdd,0xee,0xff,0x11
};

// ========================================================
// HMAC KEY
// ========================================================

const unsigned char hmac_key[] =
  "ESP32_SECRET_HMAC_KEY";

// ========================================================

WiFiClient espClient;
PubSubClient client(espClient);

// ========================================================
// WIFI CONNECTION
// ========================================================

void connectWiFi() {

  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi");

  while (WiFi.status() != WL_CONNECTED) {

    delay(500);
    Serial.print(".");
  }

  Serial.println();

  Serial.println("WiFi connected");

  Serial.print("ESP32 IP: ");

  Serial.println(WiFi.localIP());
}

// ========================================================
// MQTT CONNECTION
// ========================================================

void connectMQTT() {

  while (!client.connected()) {

    Serial.print("Connecting to MQTT...");

    String clientID = "ESP32-DHT11-";

    clientID += String(random(0xffff), HEX);

    if (client.connect(clientID.c_str())) {

      Serial.println("connected");

    } else {

      Serial.print("failed rc=");

      Serial.println(client.state());

      delay(2000);
    }
  }
}

// ========================================================
// RANDOM IV GENERATION
// ========================================================

void generateIV(unsigned char* iv) {

  esp_fill_random(iv, 16);
}

// ========================================================
// AES128 CBC ENCRYPTION
// ========================================================

bool encryptAES(
  uint8_t* input,
  size_t input_len,
  unsigned char* iv,
  uint8_t** encrypted_output,
  size_t* encrypted_len
) {

  // PKCS7 Padding

  size_t padded_len =
    ((input_len / 16) + 1) * 16;

  *encrypted_len = padded_len;

  *encrypted_output =
    (uint8_t*) malloc(padded_len);

  if (!(*encrypted_output)) {

    Serial.println("Encryption malloc failed");

    return false;
  }

  memset(*encrypted_output, 0, padded_len);

  memcpy(
    *encrypted_output,
    input,
    input_len
  );

  uint8_t pad =
    padded_len - input_len;

  for (size_t i = input_len;
       i < padded_len;
       i++) {

    (*encrypted_output)[i] = pad;
  }

  mbedtls_aes_context aes;

  mbedtls_aes_init(&aes);

  if (mbedtls_aes_setkey_enc(
        &aes,
        aes_key,
        128
      ) != 0) {

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

// ========================================================
// HMAC-SHA256
// ========================================================

bool generateHMAC(
  uint8_t* data,
  size_t data_len,
  unsigned char* output_hash
) {

  const mbedtls_md_info_t* md_info =
    mbedtls_md_info_from_type(
      MBEDTLS_MD_SHA256
    );

  if (!md_info) {

    Serial.println("SHA256 init failed");

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

    Serial.println("HMAC failed");

    return false;
  }

  return true;
}

// ========================================================
// READ DHT11 + ENCRYPT + SEND
// ========================================================

void readAndSendSensorData() {

  float temperature = dht.readTemperature();

  float humidity = dht.readHumidity();

  if (isnan(temperature) ||
      isnan(humidity)) {

    Serial.println("DHT11 read failed");

    return;
  }

  // ====================================================
  // CREATE SENSOR MESSAGE
  // ====================================================

  String sensorData =
    "TEMP:" +
    String(temperature, 2) +
    ",HUM:" +
    String(humidity, 2);

  Serial.println("Plain Data:");

  Serial.println(sensorData);

  // Convert String to bytes

  uint8_t* plain_data =
    (uint8_t*) sensorData.c_str();

  size_t plain_len =
    sensorData.length();

  // ====================================================
  // STEP 1 -> HMAC
  // ====================================================

  unsigned char hmac_output[32];

  if (!generateHMAC(
        plain_data,
        plain_len,
        hmac_output
      )) {

    return;
  }

  Serial.println("HMAC generated");

  // ====================================================
  // STEP 2 -> GENERATE IV
  // ====================================================

  unsigned char iv[16];

  generateIV(iv);

  // ====================================================
  // STEP 3 -> AES ENCRYPTION
  // ====================================================

  uint8_t* encrypted_data = NULL;

  size_t encrypted_len = 0;

  if (!encryptAES(
        plain_data,
        plain_len,
        iv,
        &encrypted_data,
        &encrypted_len
      )) {

    return;
  }

  Serial.println("Encryption successful");

  // ====================================================
  // STEP 4 -> CREATE FINAL PACKET
  // ====================================================

  size_t packet_size =
      32 +
      16 +
      encrypted_len;

  uint8_t* final_packet =
    (uint8_t*) malloc(packet_size);

  if (!final_packet) {

    Serial.println("Packet malloc failed");

    free(encrypted_data);

    return;
  }

  // [HMAC]
  memcpy(
    final_packet,
    hmac_output,
    32
  );

  // [IV]
  memcpy(
    final_packet + 32,
    iv,
    16
  );

  // [ENCRYPTED DATA]
  memcpy(
    final_packet + 48,
    encrypted_data,
    encrypted_len
  );

  // ====================================================
  // STEP 5 -> MQTT PUBLISH
  // ====================================================

  bool success = client.publish(
    sensor_topic,
    final_packet,
    packet_size
  );

  if (success) {

    Serial.println(
      "Secure sensor data published"
    );

  } else {

    Serial.println(
      "MQTT publish failed"
    );
  }

  // ====================================================
  // CLEANUP
  // ====================================================

  free(encrypted_data);

  free(final_packet);
}

// ========================================================
// SETUP
// ========================================================

void setup() {

  Serial.begin(115200);

  delay(2000);

  dht.begin();

  connectWiFi();

  client.setServer(
    mqtt_server,
    mqtt_port
  );

  connectMQTT();

  Serial.println(
    "Secure DHT11 Publisher Started"
  );
}

// ========================================================
// LOOP
// ========================================================

unsigned long lastSend = 0;

void loop() {

  if (WiFi.status() != WL_CONNECTED) {

    connectWiFi();
  }

  if (!client.connected()) {

    connectMQTT();
  }

  client.loop();

  // Send every 5 seconds

  if (millis() - lastSend > 5000) {

    lastSend = millis();

    readAndSendSensorData();
  }
}
