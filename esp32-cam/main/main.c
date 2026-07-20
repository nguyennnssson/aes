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

// Identity + credentials come from Kconfig (main/Kconfig.projbuild), NOT source.
// Set the WiFi password per build via `idf.py menuconfig` or sdkconfig.secrets —
// it is never committed (CWE-798).
#define DEVICE_ID       CONFIG_AES_DEVICE_ID
#define WIFI_SSID       CONFIG_AES_WIFI_SSID
#define WIFI_PASS       CONFIG_AES_WIFI_PASSWORD
#define MQTT_BROKER_URL CONFIG_AES_MQTT_BROKER_URI

static esp_mqtt_client_handle_t mqtt_client;
static bool mqtt_connected = false;
static bool watchdog_triggered = false;


// [CRITICAL FUNCTION]: Mark security patch, disable memory auto-flipping mechanism.
void validate_and_confirm_app(void) {
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_app_desc_t app_desc;
    esp_ota_get_partition_description(running, &app_desc);

    ESP_LOGI(TAG, "Analyzing Running Partition: %s", running->label);

    // Check whether this partition is in a pending challenge state.
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // CRITERIA MET: Rollback cancelled; this patch is accepted permanently!
            esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(TAG, "SUCCESS! Safety validation passed. Rollback canceled. Firmware signed off!");
        }
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "Network Link Established.");
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    if (event_id == MQTT_EVENT_CONNECTED) {
        ESP_LOGI(TAG, "MQTT Connected.");
        mqtt_connected = true;
        
        // Upon establishing both network and MQTT connections -> Immediately trigger the command to confirm the app is clean.
        validate_and_confirm_app();
    } else if (event_id == MQTT_EVENT_DISCONNECTED) {
        mqtt_connected = false;
    }
}

// The Watchdog Task performs a 30-second countdown to check system health.
void ota_watchdog_task(void *pvParameters) {
    ESP_LOGW(TAG, "Safety Watchdog Started. 30-second validation window open...");
    
    // Đợi 30 giây (30000 ms)
    vTaskDelay(pdMS_TO_TICKS(30000));

    // After 30 seconds, check whether the firmware has successfully authenticated with the German Pi.
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // If it remains in the PENDING state for more than 30 seconds, the code has encountered a network error or hang!
            ESP_LOGE(TAG, "CRITICAL: 30s timeout reached without MQTT handshake! Rejecting firmware...");
            watchdog_triggered = true;
            
            // Force the system to reject the faulty partition and automatically reboot to the old partition (ota_0).
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
    }
    vTaskDelete(NULL);
}

// --- Real telemetry metric sources (replace the former hardcoded placeholders) ---

// Windowed CPU utilisation (%) averaged across all cores, measured between calls.
// Uses FreeRTOS run-time stats: per-core idle-task run-time counters vs. the
// wall-clock elapsed time. Requires CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS with a
// 64-bit run-time counter (set in sdkconfig.defaults); degrades to 0 if disabled.
// The first call primes the delta window and returns 0.
static float sample_cpu_percent(void) {
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    static uint64_t prev_idle[portNUM_PROCESSORS];
    static uint64_t prev_total;
    static bool primed = false;

    uint64_t now_total = (uint64_t)esp_timer_get_time();  // run-time clock (microseconds)
    uint64_t idle_now[portNUM_PROCESSORS];
    for (int c = 0; c < portNUM_PROCESSORS; c++) {
        idle_now[c] = (uint64_t)ulTaskGetIdleRunTimeCounterForCore(c);
    }

    if (!primed) {
        for (int c = 0; c < portNUM_PROCESSORS; c++) {
            prev_idle[c] = idle_now[c];
        }
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

    if (total_delta == 0) {
        return 0.0f;
    }
    // Total available CPU time over the window = elapsed * number of cores.
    float busy = 1.0f - ((float)idle_delta / ((float)total_delta * (float)portNUM_PROCESSORS));
    float pct  = busy * 100.0f;
    if (pct < 0.0f)   pct = 0.0f;
    if (pct > 100.0f) pct = 100.0f;
    return pct;
#else
    return 0.0f;  // run-time stats not enabled in this build
#endif
}

// Link-layer packet rate (packets/sec, RX+TX) from the lwIP netif, measured
// between calls. Requires CONFIG_LWIP_STATS (set in sdkconfig.defaults); if the
// stats subsystem is compiled out the function degrades to 0 rather than failing
// the build. The first call primes the delta window and returns 0.
//
// NOTE: lwIP's STAT_COUNTER is u16 here (LWIP_STATS_LARGE is 0 and not exposed as
// a Kconfig). recv and xmit are diffed separately at the counter's native width
// so a wrap of one doesn't corrupt the other; each tolerates up to 65535 packets
// per 5 s window (~13k pps) before it aliases. That ceiling is far above this
// device's ~0 idle baseline, so the rate still rises sharply under a flood and
// trips the Monitor Agent's EWMA deviation — only the magnitude saturates at
// extreme rates. For accurate high-rate reporting, accumulate the deltas on a
// sub-second timer instead.
static float sample_packet_rate(void) {
#if LWIP_STATS && LINK_STATS
    static STAT_COUNTER prev_recv, prev_xmit;
    static uint64_t prev_us;
    static bool primed = false;

    STAT_COUNTER now_recv = STATS_GET(link.recv);
    STAT_COUNTER now_xmit = STATS_GET(link.xmit);
    uint64_t     now_us   = (uint64_t)esp_timer_get_time();

    if (!primed) {
        prev_recv = now_recv;
        prev_xmit = now_xmit;
        prev_us   = now_us;
        primed    = true;
        return 0.0f;
    }

    // Diff each counter at its native width (wrap-safe), then sum — summing first
    // would break wrap-safety when only one counter rolls over.
    STAT_COUNTER d_recv = (STAT_COUNTER)(now_recv - prev_recv);
    STAT_COUNTER d_xmit = (STAT_COUNTER)(now_xmit - prev_xmit);
    uint32_t pkt_delta  = (uint32_t)d_recv + (uint32_t)d_xmit;
    uint64_t us_delta   = now_us - prev_us;
    prev_recv = now_recv;
    prev_xmit = now_xmit;
    prev_us   = now_us;

    return (us_delta > 0) ? ((float)pkt_delta * 1000000.0f / (float)us_delta) : 0.0f;
#else
    return 0.0f;  // LWIP_STATS / LINK_STATS not enabled in this build
#endif
}

void telemetry_task(void *pvParameters) {
    while (1) {
        if (watchdog_triggered) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        // --- RAW metrics only. The Monitor Agent (Mac) owns the EWMA baseline
        //     and deviation math, so the device just reports raw readings. ---
        size_t free_heap  = esp_get_free_heap_size();
        size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
        float memory_percent = (total_heap > 0)
            ? (100.0f * (1.0f - ((float)free_heap / (float)total_heap)))
            : 0.0f;

        // Real device metrics. cpu_percent is the windowed CPU utilisation across
        // both cores (FreeRTOS run-time stats); packet_rate is link-layer RX+TX
        // packets/sec from the lwIP netif. Both rise under a live network attack,
        // so on-hardware detection now has real signal to trip on. The first
        // sample of each primes the delta window and reports 0.
        float cpu_percent      = sample_cpu_percent();
        float packet_rate      = sample_packet_rate();
        int   connection_count = mqtt_connected ? 1 : 0;

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "device_id", DEVICE_ID);
        cJSON_AddNumberToObject(root, "cpu_percent", cpu_percent);
        cJSON_AddNumberToObject(root, "memory_percent", memory_percent);
        cJSON_AddNumberToObject(root, "packet_rate", packet_rate);
        cJSON_AddNumberToObject(root, "connection_count", connection_count);

        char *json_string = cJSON_PrintUnformatted(root);

        if (mqtt_connected) {
            esp_mqtt_client_publish(mqtt_client, "aes/telemetry/" DEVICE_ID, json_string, 0, 1, 0);
            ESP_LOGI(TAG, "Telemetry stream: %s", json_string);
        } else {
            ESP_LOGW(TAG, "Telemetry hold, waiting network... %s", json_string);
        }

        cJSON_free(json_string);
        cJSON_Delete(root);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void app_main(void) {
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
    
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URL,
    };
    
    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);

    // ACTIVATE PARALLEL CHIP PROTECTION COUNTDOWN TIMER
    xTaskCreate(ota_watchdog_task, "ota_watchdog", 3072, NULL, 10, NULL);
    xTaskCreate(telemetry_task, "telemetry_task", 4096, NULL, 5, NULL);
}
