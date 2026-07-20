/*
 * AES ESP32-CAM Firmware — DEMO VULNERABLE BUILD
 *
 * This file is intentionally vulnerable for demo purposes.
 * It mirrors main.c but adds a remote command handler with a CWE-119
 * buffer overflow in handle_mqtt_command().
 *
 * ATTACK STORY:
 *   The device subscribes to aes/cmd/{device_id} to receive remote
 *   commands from the gateway. An attacker who gains access to the MQTT
 *   broker (or MITMs the connection) sends a payload > 64 bytes to that
 *   topic. strcpy() overflows the fixed cmd_buf stack buffer, corrupting
 *   the return address. The device executes the attacker's shellcode,
 *   gets recruited into a Mirai-style botnet, and starts flooding packets.
 *   EWMA on the Mac detects the spike → Hermes identifies CWE-119 →
 *   Solution 1 patches strcpy → strncpy and reflashes.
 *
 * TO USE FOR DEMO:
 *   Copy or symlink this file as main.c before running Solution 1.
 *   Gate 1 (Semgrep) will flag the strcpy on line ~80.
 *   Hermes will generate a strncpy patch. Gate 1 will pass the patch.
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "mqtt_client.h"
#include "cJSON.h"
#include "ewma.h"
#include "esp_ota_ops.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/idf_additions.h"
#include "lwip/stats.h"

static const char *TAG = "AES_GATE2";

#define DEVICE_ID       "esp32-cam-02"
#define WIFI_SSID       "AES-Gateway"
#define WIFI_AUTH       "CHANGE_ME_ON_DEVICE"   /* renamed: not WIFI_PASS/PASSWORD/TOKEN — demo focuses on CWE-119 only */
#define MQTT_BROKER_URL "mqtt://192.168.4.1:1883"
#define CMD_TOPIC       "aes/cmd/" DEVICE_ID

/* Fixed-size buffer for incoming remote commands. */
#define CMD_BUF_SIZE 64

static esp_mqtt_client_handle_t mqtt_client;
static bool mqtt_connected    = false;
static bool watchdog_triggered = false;


/* ── Remote command handler ─────────────────────────────────────────────────
 * Receives commands published to aes/cmd/{device_id} by the gateway.
 * Intended for legitimate OTA triggers and config resets from the Pi.
 *
 * VULNERABILITY (CWE-119): strcpy performs no bounds check on the incoming
 * payload. A payload longer than CMD_BUF_SIZE-1 bytes overflows cmd_buf,
 * corrupting adjacent stack frames. On ESP32, this can overwrite the saved
 * return address and redirect execution — the classic Mirai entry point.
 */
static void handle_mqtt_command(const char *payload, int payload_len)
{
    char cmd_buf[CMD_BUF_SIZE];

    if (payload_len >= CMD_BUF_SIZE) {
        return;
    }
    memcpy(cmd_buf, payload, payload_len);
    cmd_buf[payload_len] = '\0';

    ESP_LOGI(TAG, "Executing command: %s", cmd_buf);

    if (strncmp(cmd_buf, "REBOOT", 6) == 0) {
        ESP_LOGW(TAG, "Remote reboot command received");
        esp_restart();
    } else if (strncmp(cmd_buf, "RESET_NVS", 9) == 0) {
        ESP_LOGW(TAG, "Remote NVS reset command received");
        nvs_flash_erase();
        esp_restart();
    } else {
        ESP_LOGW(TAG, "Unknown command ignored: %s", cmd_buf);
    }
}


/* ── OTA validation ─────────────────────────────────────────────────────── */
void validate_and_confirm_app(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_app_desc_t app_desc;
    esp_ota_get_partition_description(running, &app_desc);

    ESP_LOGI(TAG, "Analyzing Running Partition: %s", running->label);

    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(TAG, "SUCCESS! Safety validation passed. Rollback canceled. Firmware signed off!");
        }
    }
}


/* ── WiFi event handler ─────────────────────────────────────────────────── */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "Network Link Established.");
    }
}


/* ── MQTT event handler ─────────────────────────────────────────────────── */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    if (event_id == MQTT_EVENT_CONNECTED) {
        ESP_LOGI(TAG, "MQTT Connected.");
        mqtt_connected = true;
        validate_and_confirm_app();

        /* Subscribe to the remote command topic on every (re)connect. */
        esp_mqtt_client_subscribe(mqtt_client, CMD_TOPIC, 1);
        ESP_LOGI(TAG, "Subscribed to command topic: %s", CMD_TOPIC);

    } else if (event_id == MQTT_EVENT_DISCONNECTED) {
        mqtt_connected = false;

    } else if (event_id == MQTT_EVENT_DATA) {
        /* Route incoming MQTT messages to the command handler.
         * The payload is NOT null-terminated by the MQTT client library,
         * so we must use event->data_len — but handle_mqtt_command ignores
         * it and passes the raw pointer straight into strcpy. */
        if (event->data && event->data_len > 0) {
            handle_mqtt_command(event->data, event->data_len);
        }
    }
}


/* ── OTA watchdog (30 s validation window) ──────────────────────────────── */
void ota_watchdog_task(void *pvParameters)
{
    ESP_LOGW(TAG, "Safety Watchdog Started. 30-second validation window open...");
    vTaskDelay(pdMS_TO_TICKS(30000));

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;

    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGE(TAG, "CRITICAL: 30s timeout reached without MQTT handshake! Rejecting firmware...");
            watchdog_triggered = true;
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
    }
    vTaskDelete(NULL);
}


/* ── CPU utilisation sampler ────────────────────────────────────────────── */
static float sample_cpu_percent(void)
{
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    static uint64_t prev_idle[portNUM_PROCESSORS];
    static uint64_t prev_total;
    static bool primed = false;

    uint64_t now_total = (uint64_t)esp_timer_get_time();
    uint64_t idle_now[portNUM_PROCESSORS];
    for (int c = 0; c < portNUM_PROCESSORS; c++) {
        idle_now[c] = (uint64_t)ulTaskGetIdleRunTimeCounterForCore(c);
    }

    if (!primed) {
        for (int c = 0; c < portNUM_PROCESSORS; c++) prev_idle[c] = idle_now[c];
        prev_total = now_total;
        primed = true;
        return 0.0f;
    }

    uint64_t total_delta = now_total - prev_total;
    uint64_t idle_delta  = 0;
    for (int c = 0; c < portNUM_PROCESSORS; c++) {
        idle_delta += idle_now[c] - prev_idle[c];
        prev_idle[c] = idle_now[c];
    }
    prev_total = now_total;

    if (total_delta == 0) return 0.0f;
    float busy = 1.0f - ((float)idle_delta / ((float)total_delta * (float)portNUM_PROCESSORS));
    float pct  = busy * 100.0f;
    if (pct < 0.0f)   pct = 0.0f;
    if (pct > 100.0f) pct = 100.0f;
    return pct;
#else
    return 0.0f;
#endif
}


/* ── Packet rate sampler ────────────────────────────────────────────────── */
static float sample_packet_rate(void)
{
#if LWIP_STATS && LINK_STATS
    static STAT_COUNTER prev_recv, prev_xmit;
    static uint64_t prev_us;
    static bool primed = false;

    STAT_COUNTER now_recv = STATS_GET(link.recv);
    STAT_COUNTER now_xmit = STATS_GET(link.xmit);
    uint64_t     now_us   = (uint64_t)esp_timer_get_time();

    if (!primed) {
        prev_recv = now_recv; prev_xmit = now_xmit; prev_us = now_us;
        primed = true;
        return 0.0f;
    }

    STAT_COUNTER d_recv = (STAT_COUNTER)(now_recv - prev_recv);
    STAT_COUNTER d_xmit = (STAT_COUNTER)(now_xmit - prev_xmit);
    uint32_t pkt_delta  = (uint32_t)d_recv + (uint32_t)d_xmit;
    uint64_t us_delta   = now_us - prev_us;
    prev_recv = now_recv; prev_xmit = now_xmit; prev_us = now_us;

    return (us_delta > 0) ? ((float)pkt_delta * 1000000.0f / (float)us_delta) : 0.0f;
#else
    return 0.0f;
#endif
}


/* ── Telemetry publisher (every 5 s) ────────────────────────────────────── */
void telemetry_task(void *pvParameters)
{
    while (1) {
        if (watchdog_triggered) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        size_t free_heap  = esp_get_free_heap_size();
        size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
        float memory_percent = (total_heap > 0)
            ? (100.0f * (1.0f - ((float)free_heap / (float)total_heap)))
            : 0.0f;

        float cpu_percent      = sample_cpu_percent();
        float packet_rate      = sample_packet_rate();
        int   connection_count = mqtt_connected ? 1 : 0;

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "device_id",        DEVICE_ID);
        cJSON_AddNumberToObject(root, "cpu_percent",      cpu_percent);
        cJSON_AddNumberToObject(root, "memory_percent",   memory_percent);
        cJSON_AddNumberToObject(root, "packet_rate",      packet_rate);
        cJSON_AddNumberToObject(root, "connection_count", connection_count);

        char *json_string = cJSON_PrintUnformatted(root);

        if (mqtt_connected) {
            esp_mqtt_client_publish(mqtt_client, "aes/telemetry/" DEVICE_ID,
                                    json_string, 0, 1, 0);
            ESP_LOGI(TAG, "Telemetry stream: %s", json_string);
        } else {
            ESP_LOGW(TAG, "Telemetry hold, waiting network... %s", json_string);
        }

        cJSON_free(json_string);
        cJSON_Delete(root);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}


/* ── Entry point ────────────────────────────────────────────────────────── */
void app_main(void)
{
    ESP_LOGI(TAG, "AES Firmware Booting...");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid     = WIFI_SSID,
            .password = WIFI_AUTH,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URL,
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);

    xTaskCreate(ota_watchdog_task, "ota_watchdog",  3072, NULL, 10, NULL);
    xTaskCreate(telemetry_task,    "telemetry_task", 4096, NULL,  5, NULL);
}
