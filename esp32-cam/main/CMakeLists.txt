idf_component_register(SRCS "main.c" "ewma.c"
                    INCLUDE_DIRS "."
                    REQUIRES json mqtt esp_wifi esp_event esp_netif nvs_flash app_update
                    EMBED_TXTFILES srv_cert.crt)