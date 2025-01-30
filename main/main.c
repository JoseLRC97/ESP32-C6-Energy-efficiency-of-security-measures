#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_flash.h"
#include "esp_chip_info.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"
#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"

// Tags for logs
static const char *INFO = "Info";
static const char *LIGHT = "Light";
static const char *ERROR = "Error";
static const char *WIFI = "Wifi";
static const char *SPIFF = "Spiff";

// Values for GPIO Led Strip RGB
#define BLINK_GPIO GPIO_NUM_8
static uint8_t s_led_state = 0;
static volatile bool keep_blinking = true;
static led_strip_handle_t led_strip;
static int color = 0;

// Values for WiFi connection
#define FILE_PATH "/spiffs/wifi_config.txt"
static const uint16_t MAX_APs = 25;
static char ssid[32];
static char password[64];
static int port;

// Function declarations
static void configure_Led_Strip();
static void blinkLedTask(void *param);
static void blink_Led();
static void getChipInfo();
static void init_wifi_driver();
static void wifi_scan();
static void connect_to_wifi();
ssize_t custom_getline(char **lineptr, size_t *n, FILE *stream);
static void read_config_files();
static void udp_server_task(void *pvParameters);

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

    // Inicialización de WiFi
    init_wifi_driver();

    // Leer configuraciones desde SPIFFS
    read_config_files();

    // Escanear redes WiFi
    wifi_scan();

    // Conectar a WiFi
    connect_to_wifi();

    // Tarea del servidor UDP
    xTaskCreate(udp_server_task, "udp_server_task", 4096, NULL, 5, NULL);
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
static void blinkLedTask(void *param)
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
    /* If the addressable LED is enabled */
    if (s_led_state && color == 0) {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 0, 20, 0);
        /* Refresh the strip to send data */
        led_strip_refresh(led_strip);
    } else if (s_led_state && color == 1) {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 0, 0, 20);
        /* Refresh the strip to send data */
        led_strip_refresh(led_strip);
    } else if (s_led_state && color == 2) {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 20, 20, 0); // Amarillo: Rojo + Verde
        /* Refresh the strip to send data */
        led_strip_refresh(led_strip);
    } else {
        /* Set all LED off to clear all pixels */
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
        ESP_LOGI(ERROR, "Get flash size failed");
        return;
    }

    ESP_LOGI(INFO, "%" PRIu32 "MB %s flash", flash_size / (uint32_t)(1024 * 1024), (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    ESP_LOGI(INFO, "Minimum free heap size: %" PRIu32 " bytes", esp_get_minimum_free_heap_size());
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    ESP_LOGI(LIGHT, "Stoping blinking GPIO Led becasue we finished of give information of the chip.");
    keep_blinking = false; // Stop blink LED
    vTaskDelay(3000 / portTICK_PERIOD_MS);
}

static void init_wifi_driver(void)
{
    ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB becasue we are starting a WiFi connection.");
    color = 1;
    keep_blinking = true;
    // Inicializar NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Inicializar el stack de TCP/IP
    ESP_ERROR_CHECK(esp_netif_init());

    // Crear evento loop para manejar eventos WiFi
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Inicializar WiFi
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Configurar WiFi en modo estación (station mode)
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void wifi_scan(void)
{
    // Iniciar escaneo de WiFi
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true
    };

    bool ssid_found = false;

    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));

    // Obtener resultados del escaneo
    wifi_ap_record_t ap_info[MAX_APs];
    uint16_t number = MAX_APs;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_LOGI(WIFI, "Total Wifi Access Points: %u", number);

    for (int i = 0; i < number; i++) {
        ESP_LOGI(WIFI, "SSID: %s, RSSI: %d", ap_info[i].ssid, ap_info[i].rssi);
        if (strcmp((char *)ap_info[i].ssid, ssid) == 0)
            ssid_found = true;
    }

    ESP_LOGI(WIFI, "Wifi scan finished.");

    if (!ssid_found) {
        ESP_LOGI(WIFI, "SSID '%s' not found in the scan results.\nRestarting execution in 10 seconds.", ssid);
        vTaskDelay(10000 / portTICK_PERIOD_MS); // Esperar un momento para que el log se registre
        esp_restart(); // Reiniciar el ESP32-C6
    } else
        ESP_LOGI(WIFI, "SSID '%s' found in the scan results.", ssid);
}

static void connect_to_wifi(void)
{
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "",
            .password = "",
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    // Copiar SSID y contraseña leídos del archivo de configuración
    strcpy((char*)wifi_config.sta.ssid, ssid);
    strcpy((char*)wifi_config.sta.password, password);

    int retry_count = 0;
    const int max_retries = 3;

    while (retry_count < max_retries) {
        ESP_LOGI(WIFI, "Trying to connect to %s with password: %s", ssid,password);
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
        ESP_ERROR_CHECK(esp_wifi_connect());

        // Esperar a obtener una IP
        esp_netif_ip_info_t ip_info;
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (netif == NULL) {
            ESP_LOGE(WIFI, "Failed to get network interface handle");
            return;
        }

        if (!esp_netif_is_netif_up(netif)) {
            ESP_LOGI(WIFI, "Waiting for IP...");
            vTaskDelay(10000 / portTICK_PERIOD_MS); // Esperar un poco para obtener una IP
        }

        ESP_ERROR_CHECK(esp_netif_get_ip_info(netif, &ip_info));
        if (ip_info.ip.addr != 0) {
            uint8_t mac[6];
            ESP_ERROR_CHECK(esp_netif_get_mac(netif, mac));
            
            // Imprimir IP y MAC
            ESP_LOGI(INFO, "IP Address: " IPSTR, IP2STR(&ip_info.ip));
            ESP_LOGI(INFO, "MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            keep_blinking = false;
            ESP_LOGI(LIGHT, "Stop Blinking Led Strip RGB becasue we finished WiFi connection.");
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            return; // Salir si se obtiene una IP
        }

        ESP_LOGI(WIFI, "Failed to connect. Retrying... (%d/%d)", retry_count + 1, max_retries);
        retry_count++;
    }

    ESP_LOGI(WIFI, "Failed to connect after %d attempts. Restarting in 10 seconds...", max_retries);
    vTaskDelay(10000 / portTICK_PERIOD_MS);
    esp_restart();
}

// Custom read line function
ssize_t custom_getline(char **lineptr, size_t *n, FILE *stream) {
    if (lineptr == NULL || n == NULL || stream == NULL) {
        return -1;
    }

    size_t pos = 0;
    int c;

    if (*lineptr == NULL) {
        *n = 128; // Tamaño inicial
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
static void read_config_files(void)
{
    // Inicializar SPIFFS
    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,
      .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        ESP_LOGI(SPIFF, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        return;
    } else {
        ESP_LOGI(SPIFF, "Success to initialize SPIFFS");
    }

    // Formatear SPIFFS si el montaje falla
    if (ret == ESP_ERR_NOT_FOUND || ret == ESP_ERR_NOT_FOUND) {
        ESP_LOGW(SPIFF, "Mount failed, formatting...");
        esp_spiffs_format(NULL);
        ret = esp_vfs_spiffs_register(&conf);
        if (ret != ESP_OK) {
            ESP_LOGE(SPIFF, "Failed to format SPIFFS (%s)", esp_err_to_name(ret));
            return;
        } else {
            ESP_LOGI(SPIFF, "Success to format SPIFFS");
        }
    }

    FILE* f = fopen(FILE_PATH, "r");
    if (f == NULL) {
        ESP_LOGI(SPIFF, "Failed to open file for reading");
        return;
    } else {
    ESP_LOGI(SPIFF, "File opened successfully");
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = custom_getline(&line, &len, f)) != -1) {
        if (sscanf(line, "SSID=%31s", ssid) == 1) {
            ESP_LOGI(SPIFF, "SSID: %s", ssid);
        } else if (sscanf(line, "PASSWORD=%63s", password) == 1) {
            ESP_LOGI(SPIFF, "PASSWORD: %s", password);
        } else if (sscanf(line, "PORT=%d", &port) == 1) {
            ESP_LOGI(SPIFF, "PORT: %d", port);
        }
    }

    free(line);
    fclose(f);
    esp_vfs_spiffs_unregister(conf.partition_label);
}

static void udp_server_task(void *pvParameters)
{
    char rx_buffer[128];
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
        ESP_LOGI(INFO, "Socket created");

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(ERROR, "Socket unable to bind: errno %d", errno);
            break;
        }
        ESP_LOGI(INFO, "Socket bound, port %d", port);
        color = 2;
        keep_blinking = true;
        ESP_LOGI(LIGHT, "Start Blinking Led Strip RGB becasue we are waiting data.");

        while (1) {
            ESP_LOGI(INFO, "Waiting for data");

            struct sockaddr_in source_addr;
            socklen_t socklen = sizeof(source_addr);
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(ERROR, "recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
                ESP_LOGI(INFO, "Received %d bytes from %s:", len, addr_str);
                rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string
                ESP_LOGI(INFO, "%s", rx_buffer);
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