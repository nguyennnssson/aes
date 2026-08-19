set(AES_MQTT_CA_CERT "${CMAKE_CURRENT_LIST_DIR}/srv_cert.crt")
if(NOT EXISTS "${AES_MQTT_CA_CERT}")
    message(FATAL_ERROR
        "Missing trusted MQTT CA certificate: ${AES_MQTT_CA_CERT}. "
        "Provision main/srv_cert.crt locally; never copy a CA private key.")
endif()

idf_component_register(SRCS "main.c" "ewma.c"
                    INCLUDE_DIRS "."
                    REQUIRES json mqtt esp_wifi esp_event esp_netif nvs_flash app_update
                    EMBED_TXTFILES srv_cert.crt)
