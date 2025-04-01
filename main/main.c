#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_flash.h"
#include "esp_chip_info.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "led_strip.h"
#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "cJSON.h"
#include "mbedtls/aes.h"
#include <mbedtls/gcm.h>
#include "mbedtls/ccm.h"
#include "mbedtls/des.h"
#include "mbedtls/chacha20.h"
#include <mbedtls/camellia.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/md5.h>
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

// Tags for logs
static const char *INFO = "Info";
static const char *LIGHT = "Light";
static const char *ERROR = "Error";
static const char *WIFI = "Wifi";
static const char *SPIFF = "Spiff";
static const char *UDP = "Server UDP";
static const char *TEST = "Test";
static const char *KEY = "Key";

// Values for GPIO Led Strip RGB
#define BLINK_GPIO GPIO_NUM_8
static uint8_t s_led_state = 0;
static volatile bool keep_blinking = true;
static led_strip_handle_t led_strip;
static int color = 0;

// Values for WiFi connection
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define FILE_PATH "/spiffs/wifi_config.txt"
static const int MAX_RETRY = 3;
static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;
static char ssid[32];
static char password[64];
static int port;

// Values for UDP Server
static TaskHandle_t udp_server_task_handle;
#define BUFFER_SIZE 512

// Values for AES Tests
#define BLOCK_SIZE 16
#define IV_SIZE 16
#define TWEAK_SIZE 16
#define TAG_SIZE 16

// Values for DES Tests
#define DES_BLOCK_SIZE 8

// Values for ChaCha20
#define NONCE_SIZE 12

// Values for Camellia
#define CAMELLIA_BLOCK_SIZE 16

// Variables globales para almacenar las claves en tiempo de ejecución
unsigned char private_key_2048[2048];
unsigned char public_key_2048[2048];
unsigned char private_key_4096[4096];
unsigned char public_key_4096[4096];

// Function declarations
static void configure_Led_Strip();
static void blinkLedTask(void *pvParameters);
static void blink_Led();
static void getChipInfo();
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
static void wifi_init_sta();
ssize_t custom_getline(char **lineptr, size_t *n, FILE *stream);
static void read_config_files();
static void udp_server_task(void *pvParameters);
static void select_test(cJSON *json);
static void encrypt_hash_tests(const char *data_string);
static void log_test_info_crypt(int iteration, unsigned char *crypt_data, int key_size);
static void prepare_padded_data(const char *data_string, size_t block_size, unsigned char **padded_data, unsigned char **crypt_data, unsigned char **decrypt_data, size_t *padded_length);
static void AES_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CBC_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_OFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CTR_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_GCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_XTS_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void DES_ECB_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void DES_CBC_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void DES_CFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void DES_OFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void DES_CTR_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void TDES_ECB_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void TDES_CBC_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void TDES_OFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void ChaCha20_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void Camellia_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void Camellia_CBC_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void Camellia_CFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void Camellia_OFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void Camellia_CTR_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
void log_test_info_hash(int iteration, const unsigned char *hash, size_t len);
void hash_sha224(const char *input, unsigned char *output);
void hash_sha256(const char *input, unsigned char *output);
void hash_sha384(const char *input, unsigned char *output);
void hash_sha512(const char *input, unsigned char *output);
void hash_md5(const char *input, unsigned char *output);
static void generate_rsa_keypair(unsigned char *private_key, size_t private_key_size, unsigned char *public_key, size_t public_key_size, int key_size);
static void RSA_encrypt(const unsigned char *public_key, size_t public_key_len, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_ECB_decrypt(const unsigned char *key, size_t key_size, const unsigned char *crypt_data, size_t crypt_data_len, unsigned char *plaintext, size_t *plaintext_len);
static void AES_CBC_decrypt(const unsigned char *key, size_t key_size, const unsigned char *crypt_data, size_t crypt_data_len, unsigned char *plaintext, size_t *plaintext_len);

// Main Function
void app_main(void)
{
    // Inicialización de NVS (archivo de sistema)
    ESP_ERROR_CHECK(nvs_flash_init());

    // Configuración del LED y la tarea para parpadear
    configure_Led_Strip();
    xTaskCreate(blinkLedTask, "blinkLedTask", 2048, NULL, 1, NULL); // Task to blink led GPIO

    // Mostrar información sobre el chip
    getChipInfo();

    // Leer configuraciones desde SPIFFS
    read_config_files();

    // Inicialización de WiFi
    wifi_init_sta();

    // Tarea del servidor UDP
    xTaskCreate(udp_server_task, "udp_server_task", 4096, NULL, 5, &udp_server_task_handle);
}


// Function to configure Led Strip RGB
static void configure_Led_Strip(void)
{
    ESP_LOGI(LIGHT, "Configuring Led Strip RGB");
    led_strip_config_t strip_config = {
        .strip_gpio_num = BLINK_GPIO,
        .max_leds = 1,
    };
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000, // 10MHz
        .flags.with_dma = false,
    };

    // Inicializar el strip y verificar errores
    esp_err_t err = led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip);
    if (err != ESP_OK) {
        ESP_LOGE(LIGHT, "Failed to initialize LED strip: %s", esp_err_to_name(err));
        return;
    }
    led_strip_clear(led_strip);
}

// Led Strip Function Sub Task
static void blinkLedTask(void *pvParameters)
{
    while (1) {
        if (keep_blinking) {
            blink_Led();  // Llamada para parpadear el LED
            vTaskDelay(200 / portTICK_PERIOD_MS);  // Tiempo de espera para el parpadeo (500ms)
            s_led_state = !s_led_state;  // Cambiar el estado del LED (on/off)
        } else {
            s_led_state = 1;  // Mantener el LED encendido
            blink_Led();  // LED se mantiene encendido
            vTaskDelay(1000 / portTICK_PERIOD_MS);  // Esperar un segundo (puedes ajustarlo si es necesario)
        }
    }
}

// Led Strip Blink Function
static void blink_Led()
{
    if (s_led_state && color == 0) {
        led_strip_set_pixel(led_strip, 0, 0, 20, 0);
        led_strip_refresh(led_strip);
    } else if (s_led_state && color == 1) {
        led_strip_set_pixel(led_strip, 0, 0, 0, 20);
        led_strip_refresh(led_strip);
    } else if (s_led_state && color == 2) {
        led_strip_set_pixel(led_strip, 0, 20, 20, 0);
        led_strip_refresh(led_strip);
    } else if (s_led_state && color == 3) {
        led_strip_set_pixel(led_strip, 0, 20, 0, 0);
        led_strip_refresh(led_strip);
    } else {
        led_strip_clear(led_strip);
    }
}

// Function to get the chip info
static void getChipInfo(void)
{
    ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB becasue we are starting to give information of the chip.");
    esp_chip_info_t chip_info;
    uint32_t flash_size;
    esp_chip_info(&chip_info);

    ESP_LOGI(INFO, "This is %s chip with %d CPU core(s), %s%s%s%s, ", CONFIG_IDF_TARGET, chip_info.cores,
           (chip_info.features & CHIP_FEATURE_WIFI_BGN) ? "WiFi/" : "",
           (chip_info.features & CHIP_FEATURE_BT) ? "BT" : "",
           (chip_info.features & CHIP_FEATURE_BLE) ? "BLE" : "",
           (chip_info.features & CHIP_FEATURE_IEEE802154) ? ", 802.15.4 (Zigbee/Thread)" : "");
    
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    
    unsigned major_rev = chip_info.revision / 100;
    unsigned minor_rev = chip_info.revision % 100;

    ESP_LOGI(INFO, "silicon revision v%d.%d, ", major_rev, minor_rev);
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    if(esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        ESP_LOGE(ERROR, "Get flash size failed");
        return;
    }

    ESP_LOGI(INFO, "%" PRIu32 "MB %s flash", flash_size / (uint32_t)(1024 * 1024), (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    ESP_LOGI(INFO, "Minimum free heap size: %" PRIu32 " bytes", esp_get_minimum_free_heap_size());
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    ESP_LOGI(LIGHT, "Stoping blinking GPIO Led becasue we finished of give information of the chip.");
    keep_blinking = false;
    vTaskDelay(3000 / portTICK_PERIOD_MS);
}

// WiFi event handler
static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data) {
    static wifi_ap_record_t ap_info[25];
    static uint16_t ap_count = 0;

    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(WIFI, "WiFi started, scanning...");
                esp_wifi_scan_start(NULL, false);
                break;
            case WIFI_EVENT_SCAN_DONE:
                ESP_LOGI(WIFI, "Scan done");
                esp_wifi_scan_get_ap_num(&ap_count);
                esp_wifi_scan_get_ap_records(&ap_count, ap_info);

                ESP_LOGI(WIFI, "Scanning results:");
                for (int i = 0; i < ap_count; i++) {
                    ESP_LOGI(WIFI, "SSID %d: %s, RSSI: %d dBm", i + 1, ap_info[i].ssid, ap_info[i].rssi);
                }

                vTaskDelay(2000 / portTICK_PERIOD_MS);
                bool ssid_found = false;
                for (int i = 0; i < ap_count; i++) {
                    if (strcmp((char*)ap_info[i].ssid, ssid) == 0) {
                        ssid_found = true;
                        break;
                    }
                }

                if (ssid_found) {
                    ESP_LOGI(WIFI, "SSID found, connecting...");
                    vTaskDelay(2000 / portTICK_PERIOD_MS);
                    esp_wifi_connect();
                } else {
                    ESP_LOGE(WIFI, "SSID not found in scan results");
                }
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                if (s_retry_num < MAX_RETRY) {
                    ESP_LOGW(WIFI, "Retrying connection... (%d/%d)", ++s_retry_num, MAX_RETRY);
                    ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we finished the WiFi connection.");
                    color = 1;
                    keep_blinking = true;
                    esp_wifi_connect();
                } else {
                    xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                }
                break;
            default:
                break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(WIFI, "Connected! IP Address: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we finished the WiFi connection.");
        color = 1;
        keep_blinking = false;
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// Start WiFi en mode station (STA)
static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id, instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "",
            .password = "",
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strcpy((char*)wifi_config.sta.ssid, ssid);
    strcpy((char*)wifi_config.sta.password, password);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(WIFI, "Successfully connected to WiFi");
        ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we finished the WiFi connection.");
        color = 1;
        keep_blinking = false;
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(WIFI, "Failed to connect to WiFi");
    }
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    vEventGroupDelete(s_wifi_event_group);
}

// Custom read line function
ssize_t custom_getline(char **lineptr, size_t *n, FILE *stream) {
    if (lineptr == NULL || n == NULL || stream == NULL) {
        return -1;
    }

    size_t pos = 0;
    int c;

    if (*lineptr == NULL) {
        *n = 128;
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL) {
            return -1;
        }
    }

    while ((c = fgetc(stream)) != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n * 2;
            char *new_lineptr = (char *)realloc(*lineptr, new_size);
            if (new_lineptr == NULL) {
                free(*lineptr);
                return -1;
            }
            *lineptr = new_lineptr;
            *n = new_size;
        }
        (*lineptr)[pos++] = c;
        if (c == '\n') {
            break;
        }
    }

    if (pos == 0 && c == EOF) {
        return -1;
    }

    (*lineptr)[pos] = '\0';
    return pos;
}

// Read config files function
static void read_config_files(void) {
    ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB because we are starting a WiFi connection.");
    color = 1;
    keep_blinking = true;

    // Inicializar SPIFFS
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        ESP_LOGE(SPIFF, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }

    FILE* f = fopen(FILE_PATH, "r");
    if (f == NULL) {
        ESP_LOGE(SPIFF, "Failed to open file for reading");
        esp_vfs_spiffs_unregister(conf.partition_label);
        return;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_number = 0;

    while ((read = custom_getline(&line, &len, f)) != -1) {
        line_number++;
        if (strncmp(line, "SSID=", 5) == 0) {
            sscanf(line + 5, "%[^\n]", ssid);
            ESP_LOGI(SPIFF, "Line %d: SSID: %s", line_number, ssid);
        } else if (sscanf(line, "PASSWORD=%63s", password) == 1) {
            ESP_LOGI(SPIFF, "Line %d: PASSWORD: %s", line_number, password);
        } else if (sscanf(line, "PORT=%d", &port) == 1) {
            ESP_LOGI(SPIFF, "Line %d: PORT: %d", line_number, port);
        }
    }

    free(line);
    fclose(f);
    esp_vfs_spiffs_unregister(conf.partition_label);
}

// UDP Server Task
static void udp_server_task(void *pvParameters)
{
    char rx_buffer[BUFFER_SIZE];
    char addr_str[128];
    int addr_family;
    int ip_protocol;

    while (1) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;
        
        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(ERROR, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(UDP, "Socket created");

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(ERROR, "Socket unable to bind: errno %d", errno);
            break;
        }
        ESP_LOGI(UDP, "Socket bound, port %d", port);

        while (1) {
            color = 2;
            keep_blinking = true;
            ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB becasue we are waiting data.");
            ESP_LOGI(UDP, "Waiting for data");

            struct sockaddr_in source_addr;
            socklen_t socklen = sizeof(source_addr);
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(UDP, "recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
                ESP_LOGI(UDP, "Received %d bytes from %s:", len, addr_str);
                rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string
                ESP_LOGI(UDP, "%s", rx_buffer);

                cJSON *json = cJSON_Parse(rx_buffer);
                if (json == NULL) {
                    ESP_LOGE(UDP, "Error parsing JSON");
                } else {
                    cJSON *test_type = cJSON_GetObjectItem(json, "test-type");
                    if (cJSON_IsString(test_type) && (test_type->valuestring != NULL)) {
                        select_test(json);
                    } else {
                        ESP_LOGW(UDP, "Missing or invalid 'test-type' field");
                    }

                    // Liberar la memoria del JSON
                    cJSON_Delete(json);
                }
            }
        }

        if (sock != -1) {
            ESP_LOGE(ERROR, "Shutting down socket and restarting...");
            shutdown(sock, 0);
                close(sock);
        }
    }
    vTaskDelete(NULL);
}

static void select_test(cJSON *json)
{
    ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB becasue we are checking the test type");
    color = 3;
    keep_blinking = true;
    ESP_LOGI(TEST, "Checking type of test");
    cJSON *test_type = cJSON_GetObjectItem(json, "test-type");
    if (strcmp(test_type->valuestring, "Encryption-and-hashing") == 0) {
        ESP_LOGI(TEST, "Encryption and Hashing test detected");
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        cJSON *data = cJSON_GetObjectItem(json, "data");
        if (data && cJSON_IsObject(data)) {  // Verificar que "data" sea un objeto
                const char *data_string = cJSON_PrintUnformatted(data); // Convertir el JSON a string
                if (data_string) {
                    ESP_LOGI(TEST, "Data to Encrypt and Hash: %s", data_string);
                    vTaskDelay(2000 / portTICK_PERIOD_MS);
                    ESP_LOGI(TEST, "Executing Encryption and Hashing Test in 3 seconds");
                    vTaskDelay(3000 / portTICK_PERIOD_MS);

                    encrypt_hash_tests(data_string);

                } else {
                    ESP_LOGE(TEST, "Failed to print JSON data.");
                }
            } else {
                ESP_LOGW(TEST, "Missing or invalid 'data' field");
            }
    } else {
        ESP_LOGW(TEST, "Unknow type of test");
    }
}

// Log crypt test info function
static void log_test_info_crypt(int iteration, unsigned char *crypt_data, int key_size)
{
    if (iteration % 10000 == 0) ESP_LOGI(TEST, "Iteration: %d", iteration);
    if (iteration == 1) {
        // Imprimir el resultado en formato hexadecimal usando ESP_LOGI
        char hex_output[3 * BLOCK_SIZE + 1];
        char *ptr = hex_output;

        for (int i = 0; i < BLOCK_SIZE; i++) {
            ptr += sprintf(ptr, "%02X ", crypt_data[i]);
        }
        *ptr = '\0';  // Asegurar que la cadena esté terminada en nulo
        ESP_LOGI(TEST, "Clave de %d bits: %s", key_size * 8, hex_output);
    }
}

static void log_test_info_decrypt(int iteration, unsigned char *decrypt_data)
{
    if (iteration % 10000 == 0) ESP_LOGI(TEST, "Iteration: %d", iteration);
    if (iteration == 1) {
        ESP_LOGI(TEST, "Texto desencriptado: %s", decrypt_data);
    }
}

// Encrypt and hashing tests executing function
static void encrypt_hash_tests(const char *data_string)
{
    ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we are doing Encryption and Hashing test");
    keep_blinking = false;

    // Keys of 64, 128, 192 y 256 bits
    const unsigned char key_64[8] = "12345678"; // 64 bits
    const unsigned char key_128[16] = "1234567890123456";   // 128 bits
    const unsigned char key_192[24] = "123456789012345678901234";   // 192 bits
    const unsigned char key_256[32] = "12345678901234567890123456789012";   // 256 bits

    unsigned char *crypt_data = NULL;
    unsigned char *padded_data = NULL;
    size_t padded_length = 0;
    unsigned char hash_output[64]; // SHA-512 produce hasta 64 bytes
    unsigned char *decrypted_data = NULL;
    size_t decrypted_length = 0;
    unsigned char iv[IV_SIZE];

    prepare_padded_data(data_string, BLOCK_SIZE, &padded_data, &crypt_data, &decrypted_data, &padded_length); // Padded data for AES

    /* -------------- AES ECB Test -------------- */

    ESP_LOGI(TEST, "Executing AES ECB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }
    
    ESP_LOGI(TEST, "Executing AES ECB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    ESP_LOGI(TEST, "Executing AES ECB decryption test with 128 key bits");
    // Call to measurement sensor
    AES_ECB_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
    log_test_info_crypt(1, crypt_data, sizeof(key_128));
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_decrypt(key_128, sizeof(key_128), crypt_data, padded_length, decrypted_data, &decrypted_length);
        log_test_info_decrypt(i, decrypted_data);
    }

    ESP_LOGI(TEST, "Executing AES ECB decryption test with 256 key bits");
    // Call to measurement sensor
    AES_ECB_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
    log_test_info_crypt(1, crypt_data, sizeof(key_256));
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_decrypt(key_256, sizeof(key_256), crypt_data, padded_length, decrypted_data, &decrypted_length);
        log_test_info_decrypt(i, decrypted_data);
    }

    /* -------------- AES ECB Test Finished -------------- */

    /* -------------- AES CBC Test -------------- */

    ESP_LOGI(TEST, "Executing AES CBC encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CBC encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_192, sizeof(key_192), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CBC encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    ESP_LOGI(TEST, "Executing AES CBC decryption test with 128 key bits");
    // Call to measurement sensor
    AES_CBC_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
    log_test_info_crypt(1, crypt_data, sizeof(key_128));
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_CBC_decrypt(key_128, sizeof(key_128), crypt_data, IV_SIZE + padded_length, decrypted_data, &decrypted_length);
        log_test_info_decrypt(i, decrypted_data);
    }

    ESP_LOGI(TEST, "Executing AES CBC decryption test with 192 key bits");
    // Call to measurement sensor
    AES_CBC_encrypt(key_192, sizeof(key_192), padded_data, IV_SIZE + padded_length, crypt_data);
    log_test_info_crypt(1, crypt_data, sizeof(key_192));
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_CBC_decrypt(key_192, sizeof(key_192), crypt_data, padded_length, decrypted_data, &decrypted_length);
        log_test_info_decrypt(i, decrypted_data);
    }

    ESP_LOGI(TEST, "Executing AES CBC decryption test with 256 key bits");
    // Call to measurement sensor
    AES_CBC_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
    log_test_info_crypt(1, crypt_data, sizeof(key_256));
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_CBC_decrypt(key_256, sizeof(key_256), crypt_data, IV_SIZE + padded_length, decrypted_data, &decrypted_length);
        log_test_info_decrypt(i, decrypted_data);
    }

    /* -------------- AES CBC Test Finished -------------- */

    /* -------------- AES CFB Test -------------- */
    
    ESP_LOGI(TEST, "Executing AES CFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES OFB Test -------------- */
    ESP_LOGI(TEST, "Executing AES OFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES OFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES OFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CTR Test -------------- */
    ESP_LOGI(TEST, "Executing AES CTR encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CTR encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CTR encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES GCM Test -------------- */
    ESP_LOGI(TEST, "Executing AES GCM encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES GCM encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES GCM encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES XTS Test -------------- */
    ESP_LOGI(TEST, "Executing AES XTS encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES XTS encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES XTS encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CCM Test -------------- */
    ESP_LOGI(TEST, "Executing AES CCM encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CCM encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CCM encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    prepare_padded_data(data_string, DES_BLOCK_SIZE, &padded_data, &crypt_data, &decrypted_data, &padded_length); // Padded data for DES

    /* -------------- DES ECB Test -------------- */
    ESP_LOGI(TEST, "Executing DES ECB encryption test with 64 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        DES_ECB_encrypt(key_64, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_64));
    }

    /* -------------- DES CBC Test -------------- */
    ESP_LOGI(TEST, "Executing DES CBC encryption test with 64 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        DES_CBC_encrypt(key_64, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_64));
    }

    /* -------------- DES CFB Test -------------- */
    ESP_LOGI(TEST, "Executing DES CFB encryption test with 64 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        DES_CFB_encrypt(key_64, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_64));
    }

    /* -------------- DES OFB Test -------------- */
    ESP_LOGI(TEST, "Executing DES OFB encryption test with 64 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        DES_OFB_encrypt(key_64, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_64));
    }

    /* -------------- DES CTR Test -------------- */
    ESP_LOGI(TEST, "Executing DES CTR encryption test with 64 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        DES_CTR_encrypt(key_64, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_64));
    }

    /* -------------- 3DES ECB Test -------------- */
    ESP_LOGI(TEST, "Executing 3DES ECB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_ECB_encrypt(key_128, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing 3DES ECB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_ECB_encrypt(key_192, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    /* -------------- 3DES CBC Test -------------- */
    ESP_LOGI(TEST, "Executing 3DES CBC encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_CBC_encrypt(key_128, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing 3DES CBC encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_CBC_encrypt(key_192, padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    /* -------------- 3DES OFB Test -------------- */
    ESP_LOGI(TEST, "Executing 3DES OFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_OFB_encrypt(key_128, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing 3DES OFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        TDES_OFB_encrypt(key_192, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    /* -------------- ChaCha20 Test -------------- */
    ESP_LOGI(TEST, "Executing ChaCha20 encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        ChaCha20_encrypt(key_256, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    prepare_padded_data(data_string, CAMELLIA_BLOCK_SIZE, &padded_data, &crypt_data, &decrypted_data, &padded_length); // Padded data for CAMELLIA

    /* -------------- Camellia ECB Test -------------- */
    ESP_LOGI(TEST, "Executing CAMELLIA ECB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_ECB_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA ECB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_ECB_encrypt(key_192, sizeof(key_192), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA ECB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_ECB_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- Camellia CBC Test -------------- */
    ESP_LOGI(TEST, "Executing CAMELLIA CBC encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CBC_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CBC encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CBC_encrypt(key_192, sizeof(key_192), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CBC encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CBC_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- Camellia CFB Test -------------- */
    ESP_LOGI(TEST, "Executing CAMELLIA CFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- Camellia OFB Test -------------- */
    ESP_LOGI(TEST, "Executing CAMELLIA OFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_OFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA OFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_OFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA OFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_OFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- Camellia CTR Test -------------- */
    ESP_LOGI(TEST, "Executing CAMELLIA CTR encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CTR_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CTR encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CTR_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_192));
    }

    ESP_LOGI(TEST, "Executing CAMELLIA CTR encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        Camellia_CTR_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(key_256));
    }

    /* -------------- SHA HASH TEST -------------- */
    ESP_LOGI(TEST, "Executing SHA-224 Hash Test");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        hash_sha224(data_string, hash_output);
        log_test_info_hash(i, hash_output, 28);
    }

    ESP_LOGI(TEST, "Executing SHA-256 Hash Test");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        hash_sha256(data_string, hash_output);
        log_test_info_hash(i, hash_output, 32);
    }

    ESP_LOGI(TEST, "Executing SHA-384 Hash Test");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        hash_sha384(data_string, hash_output);
        log_test_info_hash(i, hash_output, 48);
    }

    ESP_LOGI(TEST, "Executing SHA-512 Hash Test");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        hash_sha512(data_string, hash_output);
        log_test_info_hash(i, hash_output, 64);
    }

    /* -------------- MD5 HASH TEST -------------- */
    ESP_LOGI(TEST, "Executing MD5 Hash Test");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        hash_md5(data_string, hash_output);
        log_test_info_hash(i, hash_output, 16);
    }

    /* -------------- RSA Encryption TEST -------------- */
    ESP_LOGI(TEST, "Generando clave RSA de 2048 bits...");
    generate_rsa_keypair(private_key_2048, sizeof(private_key_2048), public_key_2048, sizeof(public_key_2048), 2048);
    ESP_LOGI(TEST, "Generando clave RSA de 4096 bits...");
    generate_rsa_keypair(private_key_4096, sizeof(private_key_4096), public_key_4096, sizeof(public_key_4096), 4096);
    ESP_LOGI(TEST, "\nClave pública de 2048 bits:\n%s", public_key_2048);
    ESP_LOGI(TEST, "\nClave pública de 4096 bits:\n%s", public_key_4096);
    ESP_LOGI(TEST, "\nClave privada de 2048 bits:\n%s", private_key_2048);
    ESP_LOGI(TEST, "\nClave privada de 4096 bits:\n%s", private_key_4096);

    ESP_LOGI(TEST, "Executing RSA Encryption Test with 2048 bits key");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        RSA_encrypt(public_key_2048, strlen((const char *)public_key_2048) + 1, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(public_key_2048));
    }

    ESP_LOGI(TEST, "Executing RSA Encryption Test with 4096 bits key");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        RSA_encrypt(public_key_4096, strlen((const char *)public_key_4096) + 1, data_string, sizeof(data_string), crypt_data);
        log_test_info_crypt(i, crypt_data, sizeof(public_key_4096));
    }

    /* free(crypt_data);
    free(padded_data); */
}

// Function to prepare padded data for encryption using PKCS#7
static void prepare_padded_data(const char *data_string, size_t block_size, unsigned char **padded_data, unsigned char **crypt_data, unsigned char **decrypt_data, size_t *padded_length) {
    // Obtener la longitud de data_string
    size_t data_length = strlen(data_string);

    // Calcular el número de bloques y el tamaño final con padding
    size_t padding_size = block_size - (data_length % block_size);
    *padded_length = data_length + padding_size;

    // Asignar memoria para crypt_data y padded_data
    *crypt_data = (unsigned char*) malloc(*padded_length);
    *padded_data = (unsigned char*) malloc(*padded_length);
    *decrypt_data = (unsigned char*) malloc(*padded_length);

    // Copiar data_string a padded_data
    memcpy(*padded_data, data_string, data_length);

    // Aplicar PKCS#7 padding: rellenar con el valor del tamaño de padding
    memset(*padded_data + data_length, padding_size, padding_size);
}

// AES ECB Encrypt function
static void AES_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_context aes;
    unsigned char input[AES_BLOCK_BYTES];
    unsigned char output[AES_BLOCK_BYTES];
    size_t offset = 0;

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Encripta el texto plano en bloques de 16 bytes
    while (offset < plaintext_len) {
        // Copiar el bloque de datos
        memset(input, 0, AES_BLOCK_BYTES);
        size_t block_size = (plaintext_len - offset) > AES_BLOCK_BYTES ? AES_BLOCK_BYTES : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el bloque
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, AES_BLOCK_BYTES);
        offset += AES_BLOCK_BYTES;
    }

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES CBC Encryption Function
static void AES_CBC_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_context aes;
    unsigned char iv[IV_SIZE];

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo CBC usando el IV
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, plaintext_len, iv, plaintext, crypt_data + AES_BLOCK_BYTES);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES CFB Encrypt function
static void AES_CFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_context aes;
    unsigned char iv[IV_SIZE];

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo CFB usando el IV
    size_t iv_offset = 0;
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, plaintext_len, &iv_offset, iv, (const unsigned char *)plaintext, crypt_data + AES_BLOCK_BYTES);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES OFB Encrypt function
static void AES_OFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_context aes;
    unsigned char iv[IV_SIZE];

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo OFB usando el IV
    size_t iv_offset = 0;
    mbedtls_aes_crypt_ofb(&aes, plaintext_len, &iv_offset, iv, (const unsigned char *)plaintext, crypt_data + AES_BLOCK_BYTES);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES CTR Encrypt function
static void AES_CTR_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_context aes;
    unsigned char iv[IV_SIZE];

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo CTR usando el IV
    size_t nc_off = 0;
    unsigned char stream_block[16];
    mbedtls_aes_crypt_ctr(&aes, plaintext_len, &nc_off, iv, stream_block, (const unsigned char *)plaintext, crypt_data + AES_BLOCK_BYTES);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES GCM Encrypt function
static void AES_GCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_gcm_context gcm;
    unsigned char iv[IV_SIZE]; // IV size for GCM is typically 12 bytes
    unsigned char tag[TAG_SIZE]; // Buffer para almacenar la etiqueta de autenticación

    // Inicializa el contexto de GCM
    mbedtls_gcm_init(&gcm);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo GCM usando el IV
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, IV_SIZE, NULL, 0, (const unsigned char *)plaintext, crypt_data + IV_SIZE, TAG_SIZE, tag);

    // Liberar recursos
    mbedtls_gcm_free(&gcm);
}

// Función para cifrar con AES-XTS
void AES_XTS_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_aes_xts_context aes_xts;
    unsigned char tweak[TWEAK_SIZE]; // El tweak es como un "IV", pero basado en el número de sector/bloque.
    esp_fill_random(tweak, TWEAK_SIZE);

    // Inicializar AES-XTS y configurar la clave
    mbedtls_aes_xts_init(&aes_xts);
    mbedtls_aes_xts_setkey_enc(&aes_xts, key, key_size * 8);

    // Cifrar en modo XTS
    mbedtls_aes_crypt_xts(&aes_xts, MBEDTLS_AES_ENCRYPT, plaintext_len, tweak, (const unsigned char *)plaintext, crypt_data);

    // Liberar memoria
    mbedtls_aes_xts_free(&aes_xts);
}

// AES CCM Encrypt function
static void AES_CCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_ccm_context ccm;
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];

    // Inicializa el contexto de CCM
    mbedtls_ccm_init(&ccm);

    // Generar IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, IV_SIZE);

    // Configura la clave según el tamaño especificado
    mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, key_size * 8);

    // Copia el IV generado al comienzo del crypt_data
    memcpy(crypt_data, iv, IV_SIZE);

    // Encripta el bloque en modo CCM usando el IV
    mbedtls_ccm_encrypt_and_tag(&ccm, plaintext_len, iv, IV_SIZE, NULL, 0, (const unsigned char *)plaintext, crypt_data + IV_SIZE, tag, TAG_SIZE);

    // Copia el tag al final del crypt_data
    memcpy(crypt_data + IV_SIZE + plaintext_len, tag, TAG_SIZE);

    // Liberar recursos
    mbedtls_ccm_free(&ccm);
}

// DES ECB Encrypt function
static void DES_ECB_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des_context des;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de DES
    mbedtls_des_init(&des);

    // Configura la clave
    mbedtls_des_setkey_enc(&des, key);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el bloque
        mbedtls_des_crypt_ecb(&des, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, DES_BLOCK_SIZE);
        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des_free(&des);
}

// DES CBC Encrypt function
static void DES_CBC_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des_context des;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    unsigned char iv[DES_BLOCK_SIZE];
    size_t offset = 0;
    
    // Inicializa el contexto de DES y configura la clave
    mbedtls_des_init(&des);
    mbedtls_des_setkey_enc(&des, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // XOR con el IV (primer bloque) o con el bloque cifrado anterior (siguientes bloques)
        for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
            input[i] ^= iv[i];
        }

        // Encriptar el bloque
        mbedtls_des_crypt_ecb(&des, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, DES_BLOCK_SIZE);

        // Actualizar el IV para el siguiente bloque
        memcpy(iv, output, DES_BLOCK_SIZE);

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des_free(&des);
}

// DES CFB Encrypt function
static void DES_CFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des_context des;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    unsigned char iv[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de DES y configura la clave
    mbedtls_des_init(&des);
    mbedtls_des_setkey_enc(&des, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el IV
        mbedtls_des_crypt_ecb(&des, iv, output);

        // XOR con el bloque de texto plano
        for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
            crypt_data[offset + i] = input[i] ^ output[i];
        }

        // Actualizar el IV para el siguiente bloque
        memcpy(iv, crypt_data + offset, DES_BLOCK_SIZE);

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des_free(&des);
}

// DES OFB Encrypt function
static void DES_OFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des_context des;
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de DES y configura la clave
    mbedtls_des_init(&des);
    mbedtls_des_setkey_enc(&des, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Encriptar el IV
        mbedtls_des_crypt_ecb(&des, iv, output);

        // XOR con el bloque de texto plano
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        for (size_t i = 0; i < block_size; i++) {
            crypt_data[offset + i] = plaintext[offset + i] ^ output[i];
        }

        // Actualizar el IV para el siguiente bloque (pero no el texto cifrado)
        memcpy(iv, output, DES_BLOCK_SIZE);

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des_free(&des);
}

// DES CTR Encrypt function
static void DES_CTR_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des_context des;
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    unsigned char counter[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de DES y configura la clave
    mbedtls_des_init(&des);
    mbedtls_des_setkey_enc(&des, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);
    memcpy(counter, iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Encriptar el contador
        mbedtls_des_crypt_ecb(&des, counter, output);

        // XOR con el bloque de texto plano
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        for (size_t i = 0; i < block_size; i++) {
            crypt_data[offset + i] = plaintext[offset + i] ^ output[i];
        }

        // Incrementar el contador para el siguiente bloque
        for (int i = DES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter[i]) break;
        }

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des_free(&des);
}

// 3DES ECB Encrypt function
static void TDES_ECB_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des3_context des3;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de 3DES
    mbedtls_des3_init(&des3);

    // Configura la clave para 3DES
    mbedtls_des3_set3key_enc(&des3, key);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el bloque
        mbedtls_des3_crypt_ecb(&des3, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, block_size);
        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des3_free(&des3);
}

// 3DES CBC Encrypt function
static void TDES_CBC_encrypt(const unsigned char *key, unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des3_context des3;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    unsigned char iv[DES_BLOCK_SIZE];
    size_t offset = 0;
    
    // Inicializa el contexto de 3DES y configura la clave
    mbedtls_des3_init(&des3);
    mbedtls_des3_set3key_enc(&des3, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // XOR con el IV (primer bloque) o con el bloque cifrado anterior (siguientes bloques)
        for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
            input[i] ^= iv[i];
        }

        // Encriptar el bloque
        mbedtls_des3_crypt_ecb(&des3, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, block_size);

        // Actualizar el IV para el siguiente bloque
        memcpy(iv, output, DES_BLOCK_SIZE);

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des3_free(&des3);
}

// 3DES OFB Encrypt function
static void TDES_OFB_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_des3_context des3;
    unsigned char input[DES_BLOCK_SIZE];
    unsigned char output[DES_BLOCK_SIZE];
    unsigned char iv[DES_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de 3DES y configura la clave
    mbedtls_des3_init(&des3);
    mbedtls_des3_set3key_enc(&des3, key);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, DES_BLOCK_SIZE);

    // Inicializa el vector de inicialización (IV) para OFB
    unsigned char ofb_iv[DES_BLOCK_SIZE];
    memcpy(ofb_iv, iv, DES_BLOCK_SIZE);

    // Encripta el texto plano en bloques de DES_BLOCK_SIZE
    while (offset < plaintext_len) {

        // Copiar el bloque de datos
        memset(input, 0, DES_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > DES_BLOCK_SIZE ? DES_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el IV usando ECB y generar la siguiente parte del keystream
        mbedtls_des3_crypt_ecb(&des3, ofb_iv, output);

        // XOR el keystream con el texto plano para obtener el texto cifrado
        for (size_t i = 0; i < block_size; i++) {
            output[i] ^= input[i];
        }

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, block_size);

        // Actualizar el IV para el siguiente bloque
        memcpy(ofb_iv, output, DES_BLOCK_SIZE);

        offset += DES_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_des3_free(&des3);
}

// ChaCha20 Encrypt function
static void ChaCha20_encrypt(const unsigned char *key, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_chacha20_context chacha20;
    unsigned char nonce[NONCE_SIZE];  // ChaCha20 utiliza un nonce de 12 bytes

     // Inicializa el contexto de ChaCha20 y configura la clave
     mbedtls_chacha20_init(&chacha20);
     mbedtls_chacha20_setkey(&chacha20, key);

    esp_fill_random(nonce, NONCE_SIZE); // Generación aleatoria del nonce

    // Configura el contexto de ChaCha20 con la clave y el nonce
    mbedtls_chacha20_starts(&chacha20, nonce, 0);

    // Encripta el texto plano en un solo paso
    mbedtls_chacha20_update(&chacha20, plaintext_len, (const unsigned char*)plaintext, crypt_data);

    // Liberar recursos
    mbedtls_chacha20_free(&chacha20);
}

// Camellia ECB Encrypt function
static void Camellia_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_camellia_context camellia;
    unsigned char input[CAMELLIA_BLOCK_SIZE];
    unsigned char output[CAMELLIA_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de Camellia
    mbedtls_camellia_init(&camellia);

    // Configura la clave según el tamaño especificado
    mbedtls_camellia_setkey_enc(&camellia, key, key_size * 8);

    // Encripta el texto plano en bloques de 16 bytes
    while (offset < plaintext_len) {
        // Copiar el bloque de datos
        memset(input, 0, 16);
        size_t block_size = (plaintext_len - offset) > CAMELLIA_BLOCK_SIZE ? CAMELLIA_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el bloque
        mbedtls_camellia_crypt_ecb(&camellia, MBEDTLS_CAMELLIA_ENCRYPT, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, CAMELLIA_BLOCK_SIZE);
        offset += CAMELLIA_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_camellia_free(&camellia);
}

// Camellia CBC Encrypt function
static void Camellia_CBC_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_camellia_context camellia;
    unsigned char input[CAMELLIA_BLOCK_SIZE];
    unsigned char output[CAMELLIA_BLOCK_SIZE];
    unsigned char iv[CAMELLIA_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de Camellia
    mbedtls_camellia_init(&camellia);

    // Configura la clave según el tamaño especificado
    mbedtls_camellia_setkey_enc(&camellia, key, key_size * 8);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, CAMELLIA_BLOCK_SIZE);

    // Encripta el texto plano en bloques de 16 bytes
    while (offset < plaintext_len) {
        // Copiar el bloque de datos
        memset(input, 0, 16);
        size_t block_size = (plaintext_len - offset) > CAMELLIA_BLOCK_SIZE ? CAMELLIA_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Hacer XOR con el IV actual
        for (size_t i = 0; i < CAMELLIA_BLOCK_SIZE; ++i) {
            input[i] ^= iv[i];
        }

        // Encriptar el bloque
        mbedtls_camellia_crypt_ecb(&camellia, MBEDTLS_CAMELLIA_ENCRYPT, input, output);

        // Copiar el bloque cifrado a crypt_data
        memcpy(crypt_data + offset, output, CAMELLIA_BLOCK_SIZE);

        // Actualizar el IV actual con el bloque cifrado
        memcpy(iv, output, CAMELLIA_BLOCK_SIZE);

        offset += CAMELLIA_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_camellia_free(&camellia);
}

// Camellia CFB Encrypt function
static void Camellia_CFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_camellia_context camellia;
    unsigned char input[CAMELLIA_BLOCK_SIZE];
    unsigned char output[CAMELLIA_BLOCK_SIZE];
    unsigned char iv[CAMELLIA_BLOCK_SIZE];
    size_t offset = 0;

    // Inicializa el contexto de Camellia
    mbedtls_camellia_init(&camellia);

    // Configura la clave según el tamaño especificado
    mbedtls_camellia_setkey_enc(&camellia, key, key_size * 8);

    // Genera el IV aleatorio usando el generador de hardware TRNG del ESP32-C6
    esp_fill_random(iv, CAMELLIA_BLOCK_SIZE);

    // Encripta el texto plano en bloques de 16 bytes
    while (offset < plaintext_len) {
        // Copiar el bloque de datos
        memset(input, 0, CAMELLIA_BLOCK_SIZE);
        size_t block_size = (plaintext_len - offset) > CAMELLIA_BLOCK_SIZE ? CAMELLIA_BLOCK_SIZE : (plaintext_len - offset);
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el IV actual usando ECB para obtener el vector intermedio
        mbedtls_camellia_crypt_ecb(&camellia, MBEDTLS_CAMELLIA_ENCRYPT, iv, output);

        // Hacer XOR del vector intermedio con el texto plano para obtener el texto cifrado
        for (size_t i = 0; i < block_size; ++i) {
            crypt_data[offset + i] = input[i] ^ output[i];
        }

        // Actualizar el IV con el texto cifrado para el siguiente bloque
        memcpy(iv, crypt_data + offset, block_size);

        offset += CAMELLIA_BLOCK_SIZE;
    }

    // Liberar recursos
    mbedtls_camellia_free(&camellia);
}

// Camellia OFB Encrypt function
static void Camellia_OFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_camellia_context camellia;
    unsigned char iv[CAMELLIA_BLOCK_SIZE]; // Vector de inicialización
    unsigned char output[CAMELLIA_BLOCK_SIZE]; // Bloque de salida
    size_t offset = 0;

    // Inicializa el contexto de Camellia
    mbedtls_camellia_init(&camellia);

    // Configura la clave según el tamaño especificado
    mbedtls_camellia_setkey_enc(&camellia, key, key_size * 8);

    // Genera un IV aleatorio
    esp_fill_random(iv, CAMELLIA_BLOCK_SIZE);

    // Encripta el texto plano en bloques de tamaño definido
    while (offset < plaintext_len) {
        // Cifra el IV actual con el modo ECB para generar el bloque de cifrado
        mbedtls_camellia_crypt_ecb(&camellia, MBEDTLS_CAMELLIA_ENCRYPT, iv, output);

        // Hacer XOR del bloque de cifrado con el texto plano
        size_t block_size = (plaintext_len - offset) > CAMELLIA_BLOCK_SIZE ? CAMELLIA_BLOCK_SIZE : (plaintext_len - offset);
        for (size_t i = 0; i < block_size; ++i) {
            crypt_data[offset + i] = plaintext[offset + i] ^ output[i];
        }

        // Actualizar el IV para el siguiente bloque (en OFB, el IV es reemplazado por el bloque de salida)
        memcpy(iv, output, CAMELLIA_BLOCK_SIZE);

        offset += block_size;
    }

    // Liberar recursos
    mbedtls_camellia_free(&camellia);
}

// Camellia CTR Encrypt function
static void Camellia_CTR_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_camellia_context camellia;
    unsigned char nonce_counter[CAMELLIA_BLOCK_SIZE]; // Nonce + Counter
    unsigned char stream_block[CAMELLIA_BLOCK_SIZE]; // Bloque de cifrado
    size_t offset = 0;

    // Inicializa el contexto de Camellia
    mbedtls_camellia_init(&camellia);

    // Configura la clave según el tamaño especificado
    mbedtls_camellia_setkey_enc(&camellia, key, key_size * 8);

    // Generar un nonce aleatorio (parte inicial del nonce + counter)
    esp_fill_random(nonce_counter, CAMELLIA_BLOCK_SIZE);

    // Encripta el texto plano en bloques
    while (offset < plaintext_len) {
        // Cifra el nonce_counter para generar el bloque de flujo (stream block)
        mbedtls_camellia_crypt_ecb(&camellia, MBEDTLS_CAMELLIA_ENCRYPT, nonce_counter, stream_block);

        // Hacer XOR entre el bloque de flujo y el texto plano
        size_t block_size = (plaintext_len - offset) > CAMELLIA_BLOCK_SIZE ? CAMELLIA_BLOCK_SIZE : (plaintext_len - offset);
        for (size_t i = 0; i < block_size; ++i) {
            crypt_data[offset + i] = plaintext[offset + i] ^ stream_block[i];
        }

        // Incrementar el contador (últimos bytes del nonce_counter)
        for (int i = CAMELLIA_BLOCK_SIZE - 1; i >= 0; --i) {
            if (++nonce_counter[i]) {
                break;
            }
        }

        offset += block_size;
    }

    // Liberar recursos
    mbedtls_camellia_free(&camellia);
}

// SHA-224
void hash_sha224(const char *input, unsigned char *output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 1); // 1 indica SHA-224
    mbedtls_sha256_update(&ctx, (const unsigned char *)input, strlen(input));
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

// SHA-256
void hash_sha256(const char *input, unsigned char *output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 indica SHA-256
    mbedtls_sha256_update(&ctx, (const unsigned char *)input, strlen(input));
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

// SHA-384
void hash_sha384(const char *input, unsigned char *output) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 1); // 1 indica SHA-384
    mbedtls_sha512_update(&ctx, (const unsigned char *)input, strlen(input));
    mbedtls_sha512_finish(&ctx, output);
    mbedtls_sha512_free(&ctx);
}

// SHA-512
void hash_sha512(const char *input, unsigned char *output) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0); // 0 indica SHA-512
    mbedtls_sha512_update(&ctx, (const unsigned char *)input, strlen(input));
    mbedtls_sha512_finish(&ctx, output);
    mbedtls_sha512_free(&ctx);
}

void log_test_info_hash(int iteration, const unsigned char *hash, size_t len) {
    if (iteration % 10000 == 0) ESP_LOGI(TEST, "Iteration: %d", iteration);
    if (iteration == 1) {
        char hash_string[len * 2 + 1]; // Buffer para almacenar el hash en formato hexadecimal
        for (size_t i = 0; i < len; i++) {
            sprintf(&hash_string[i * 2], "%02x", hash[i]);
        }
        hash_string[len * 2] = '\0'; // Asegurar que el string está terminado en nulo

        // Usar ESP_LOGI para imprimir el hash
        ESP_LOGI(TEST, "Hash: %s", hash_string);
    }
}

// Función para calcular el hash MD5
void hash_md5(const char *input, unsigned char *output) {
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);

    // Inicia el contexto de MD5
    mbedtls_md5_starts(&ctx);

    // Procesa el string a hashear
    mbedtls_md5_update(&ctx, (const unsigned char *)input, strlen(input));

    // Finaliza el hashing y almacena el resultado en output
    mbedtls_md5_finish(&ctx, output);

    // Libera la memoria del contexto
    mbedtls_md5_free(&ctx);
}

// Función genérica para generar claves RSA
static void generate_rsa_keypair(unsigned char *private_key, size_t private_key_size, unsigned char *public_key, size_t public_key_size, int key_size) {
    mbedtls_pk_context key;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "rsa_gen";

    // Inicializa contextos
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Configura el generador de números aleatorios
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(KEY, "Error inicializando el generador aleatorio: %d\n", ret);
        return;
    }

    // Configura el contexto para clave RSA
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        ESP_LOGE(KEY, "Error configurando el contexto de clave: %d\n", ret);
        return;
    }

    // Genera la clave RSA con el tamaño especificado
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, key_size, 65537);
        if (ret != 0) {
        ESP_LOGE(KEY, "Error generando clave RSA (%d bits): %d\n", key_size, ret);
        return;
    }

    // Exporta la clave privada en formato PEM
    memset(private_key, 0, private_key_size);
    ret = mbedtls_pk_write_key_pem(&key, private_key, private_key_size);
    if (ret == 0) {
        ESP_LOGI(KEY, "Clave privada (%d bits) generada correctamente.\n", key_size);
    } else {
        ESP_LOGE(KEY, "Error exportando la clave privada (%d bits): %d\n", key_size, ret);
    }

    // Exporta la clave pública en formato PEM
    memset(public_key, 0, public_key_size);
    ret = mbedtls_pk_write_pubkey_pem(&key, public_key, public_key_size);
    if (ret == 0) {
        ESP_LOGI(KEY, "Clave pública (%d bits) generada correctamente.\n", key_size);
    } else {
        ESP_LOGE(KEY, "Error exportando la clave pública (%d bits): %d\n", key_size, ret);
    }

    // Libera recursos
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

static void RSA_encrypt(const unsigned char *public_key, size_t public_key_len, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_encrypt";
    size_t offset = 0;
    unsigned char input[512];  // Máximo permitido por RSA de 4096 bits con padding
    unsigned char output[512]; // Ajusta según el tamaño de la clave pública
    int ret;

    // Inicializa los contextos
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Configura el generador de números aleatorios
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TEST, "Error inicializando el generador aleatorio: %d", ret);
        return;
    }

    ESP_LOGI(TEST, "Cargar la clave pública");
    // Cargar la clave pública proporcionada
    ret = mbedtls_pk_parse_public_key(&pk, public_key, public_key_len);
    if (ret != 0) {
        ESP_LOGE(TEST, "Error cargando la clave pública: %d", ret);
        return;
    }

    ESP_LOGI(TEST, "Comprobar que la clave cargada es de tipo RSA");
    // Comprueba que la clave cargada es de tipo RSA
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        ESP_LOGE(TEST, "La clave proporcionada no es una clave RSA.");
        mbedtls_pk_free(&pk);
        return;
    }

    ESP_LOGI(TEST, "Configurar padding");
    // Obtén el contexto RSA y configura el padding
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    size_t rsa_len = mbedtls_rsa_get_len(rsa); // Obtiene el tamaño de la clave en bytes
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    ESP_LOGI(TEST, "Encriptar el texto plano en bloques");
    // Encripta el texto plano en bloques
    while (offset < plaintext_len) {
        // Copiar el bloque de datos
        memset(input, 0, rsa_len);  // Asegúrate de que el buffer sea compatible con la longitud de la clave
        size_t block_size = (plaintext_len - offset) > (rsa_len - 42) 
                                ? (rsa_len - 42) 
                                : (plaintext_len - offset); // Tamaño máximo permitido por el padding
        memcpy(input, plaintext + offset, block_size);

        // Encriptar el bloque
        ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 
                                        block_size, input, output);
        if (ret != 0) {
            ESP_LOGE(TEST, "Error cifrando el bloque: %d", ret);
            break;
        }

        // Copiar el bloque cifrado al buffer de salida
        memcpy(crypt_data + offset, output, rsa_len);
        offset += block_size;
    }

    ESP_LOGI(TEST, "Cifrado RSA completado.");

    // Liberar recursos
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// AES ECB Decrypt function
static void AES_ECB_decrypt(const unsigned char *key, size_t key_size, const unsigned char *crypt_data, size_t crypt_data_len, unsigned char *plaintext, size_t *plaintext_len) {
    mbedtls_aes_context aes;
    unsigned char input[AES_BLOCK_BYTES];
    unsigned char output[AES_BLOCK_BYTES];
    size_t offset = 0;

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_dec(&aes, key, key_size * 8);

    // Desencripta el texto cifrado en bloques de 16 bytes
    while (offset < crypt_data_len) {
        // Copiar el bloque de datos cifrados
        memset(input, 0, AES_BLOCK_BYTES);
        size_t block_size = (crypt_data_len - offset) > AES_BLOCK_BYTES ? AES_BLOCK_BYTES : (crypt_data_len - offset);
        memcpy(input, crypt_data + offset, block_size);

        // Desencriptar el bloque
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input, output);

        // Copiar el bloque desencriptado a plaintext
        memcpy(plaintext + offset, output, AES_BLOCK_BYTES);
        offset += AES_BLOCK_BYTES;
    }

    // Calcula la longitud original del texto plano eliminando el padding PKCS#7
    unsigned char padding_size = plaintext[offset - 1];
    *plaintext_len = crypt_data_len - padding_size;
    memset(plaintext + *plaintext_len, 0, padding_size);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}

// AES CBC Decrypt function
static void AES_CBC_decrypt(const unsigned char *key, size_t key_size, const unsigned char *crypt_data, size_t crypt_data_len, unsigned char *plaintext, size_t *plaintext_len) {
    mbedtls_aes_context aes;
    unsigned char iv[IV_SIZE]; // Buffer para almacenar el IV extraído
    size_t offset = IV_SIZE;  // Comenzar después del IV en los datos cifrados
    unsigned char output[AES_BLOCK_BYTES];

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_dec(&aes, key, key_size * 8);

    // Extraer el IV desde el comienzo de los datos cifrados
    memcpy(iv, crypt_data, IV_SIZE);

    // Desencripta el texto cifrado en bloques de 16 bytes, excluyendo el IV
    while (offset < crypt_data_len) {
        // Desencriptar el bloque actual
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, AES_BLOCK_BYTES, iv, crypt_data + offset, output);

        // Copiar el bloque desencriptado a plaintext
        memcpy(plaintext + (offset - IV_SIZE), output, AES_BLOCK_BYTES);
        offset += AES_BLOCK_BYTES;
    }

    // Calcular la longitud original del texto plano eliminando el padding PKCS#7
    size_t decrypted_len = crypt_data_len - IV_SIZE; // Longitud del texto cifrado menos el IV
    unsigned char padding_size = plaintext[decrypted_len - 1]; // Último byte del texto desencriptado
    *plaintext_len = decrypted_len - padding_size;
    // Eliminar físicamente el padding sobrescribiéndolo con ceros
    memset(plaintext + *plaintext_len, 0, padding_size);

    // Liberar recursos
    mbedtls_aes_free(&aes);
}