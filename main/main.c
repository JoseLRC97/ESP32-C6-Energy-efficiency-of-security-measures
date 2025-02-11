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

// Tags for logs
static const char *INFO = "Info";
static const char *LIGHT = "Light";
static const char *ERROR = "Error";
static const char *WIFI = "Wifi";
static const char *SPIFF = "Spiff";
static const char *UDP = "Server UDP";
static const char *TEST = "Test";

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
static void log_test_info(int iteration, unsigned char *crypt_data, int key_size);
static void prepare_padded_data(const char *data_string, unsigned char **padded_data, unsigned char **crypt_data, size_t *padded_length);
static void AES_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, unsigned char *crypt_data);
static void AES_CBC_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_OFB_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CTR_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_GCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_XTS_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);
static void AES_CCM_encrypt(const unsigned char *key, size_t key_size, const char *plaintext, size_t plaintext_len, unsigned char *crypt_data);

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
        if (sscanf(line, "SSID=%31s", ssid) == 1) {
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
static void log_test_info(int iteration, unsigned char *crypt_data, int key_size)
{
    if (iteration % 5000 == 0) ESP_LOGI(TEST, "Iteration: %d", iteration);
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

// Encrypt and hashing tests executing function
static void encrypt_hash_tests(const char *data_string)
{
    ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we are doing Encryption and Hashing test");
    keep_blinking = false;

    // Keys of 128, 192 y 256 bits
    const unsigned char key_128[16] = "1234567890123456";   // 128 bits
    const unsigned char key_192[24] = "123456789012345678901234";   // 192 bits
    const unsigned char key_256[32] = "12345678901234567890123456789012";   // 256 bits

    unsigned char *crypt_data = NULL;
    unsigned char *padded_data = NULL;
    size_t padded_length = 0;

    prepare_padded_data(data_string, &padded_data, &crypt_data, &padded_length);

    /* -------------- AES ECB Test -------------- */
    ESP_LOGI(TEST, "Executing AES ECB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_encrypt(key_128, sizeof(key_128), padded_data, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES ECB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=10000000; i++) {
        AES_ECB_encrypt(key_192, sizeof(key_192), padded_data, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES ECB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=1000000; i++) {
        AES_ECB_encrypt(key_256, sizeof(key_256), padded_data, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CBC Test -------------- */
    ESP_LOGI(TEST, "Executing AES CBC encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_128, sizeof(key_128), padded_data, padded_length, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CBC encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_192, sizeof(key_192), padded_data, padded_length, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CBC encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CBC_encrypt(key_256, sizeof(key_256), padded_data, padded_length, crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CFB Test -------------- */
    ESP_LOGI(TEST, "Executing AES CFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES OFB Test -------------- */
    ESP_LOGI(TEST, "Executing AES OFB encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES OFB encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES OFB encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_OFB_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CTR Test -------------- */
    ESP_LOGI(TEST, "Executing AES CTR encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CTR encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CTR encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CTR_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES GCM Test -------------- */
    ESP_LOGI(TEST, "Executing AES GCM encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES GCM encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES GCM encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_GCM_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES XTS Test -------------- */
    ESP_LOGI(TEST, "Executing AES XTS encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES XTS encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES XTS encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_XTS_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* -------------- AES CCM Test -------------- */
    ESP_LOGI(TEST, "Executing AES CCM encryption test with 128 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_128, sizeof(key_128), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_128));
    }

    ESP_LOGI(TEST, "Executing AES CCM encryption test with 192 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_192, sizeof(key_192), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_192));
    }
    
    ESP_LOGI(TEST, "Executing AES CCM encryption test with 256 key bits");
    // Call to measurement sensor
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    for(int i=1; i<=100000; i++) {
        AES_CCM_encrypt(key_256, sizeof(key_256), data_string, sizeof(data_string), crypt_data);
        log_test_info(i, crypt_data, sizeof(key_256));
    }

    /* free(crypt_data);
    free(padded_data); */
}

// Function to prepare padded data for encryption
static void prepare_padded_data(const char *data_string, unsigned char **padded_data, unsigned char **crypt_data, size_t *padded_length) {
    // Obtener la longitud de data_string
    size_t data_length = strlen(data_string);
    
    // Calcular el número de bloques y el tamaño del último bloque con padding
    size_t num_blocks = (data_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    *padded_length = num_blocks * BLOCK_SIZE;

    // Asignar memoria para crypt_data y padded_data
    *crypt_data = (unsigned char*) malloc(*padded_length);
    *padded_data = (unsigned char*) malloc(*padded_length);

    // Copiar data_string a padded_data y aplicar padding
    memcpy(*padded_data, data_string, data_length);
    for(size_t i = data_length; i < *padded_length; i++) {
        (*padded_data)[i] = (unsigned char)(*padded_length - data_length);
    }
}

// AES ECB Encryption Function
static void AES_ECB_encrypt(const unsigned char *key, size_t key_size, const unsigned char *plaintext, unsigned char *crypt_data) {
    mbedtls_aes_context aes;

    // Inicializa el contexto de AES
    mbedtls_aes_init(&aes);

    // Configura la clave según el tamaño especificado
    mbedtls_aes_setkey_enc(&aes, key, key_size * 8);

    // Encripta el bloque en modo ECB
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, crypt_data);

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
    memcpy(crypt_data, iv, 16);

    // Encripta el bloque en modo CBC usando el IV
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, plaintext_len, iv, plaintext, crypt_data + 16);

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
    memcpy(crypt_data, iv, 16);

    // Encripta el bloque en modo CFB usando el IV
    size_t iv_offset = 0;
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, plaintext_len, &iv_offset, iv, (const unsigned char *)plaintext, crypt_data + 16);

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
    memcpy(crypt_data, iv, 16);

    // Encripta el bloque en modo OFB usando el IV
    size_t iv_offset = 0;
    mbedtls_aes_crypt_ofb(&aes, plaintext_len, &iv_offset, iv, (const unsigned char *)plaintext, crypt_data + 16);

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
    memcpy(crypt_data, iv, 16);

    // Encripta el bloque en modo CTR usando el IV
    size_t nc_off = 0;
    unsigned char stream_block[16];
    mbedtls_aes_crypt_ctr(&aes, plaintext_len, &nc_off, iv, stream_block, (const unsigned char *)plaintext, crypt_data + 16);

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
    memcpy(crypt_data, iv, 12);

    // Encripta el bloque en modo GCM usando el IV
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, 12, NULL, 0, (const unsigned char *)plaintext, crypt_data + 12, TAG_SIZE, tag);

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