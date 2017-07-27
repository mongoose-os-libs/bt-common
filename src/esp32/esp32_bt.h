/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_

#include <stdlib.h>

#include "esp_bt_defs.h"
#include "esp_gatt_defs.h"
#include "esp_gatts_api.h"

#define BT_ADDR_STR_LEN (ESP_BD_ADDR_LEN * 2 + ESP_BD_ADDR_LEN)
#define BT_UUID_STR_LEN (ESP_UUID_LEN_128 * 2 + ESP_UUID_LEN_128)

#ifdef __cplusplus
extern "C" {
#endif

const uint16_t primary_service_uuid;
const uint16_t char_decl_uuid;
const uint8_t char_prop_read_write;
const uint8_t char_prop_read_notify;
const uint8_t char_prop_write;

const char *mgos_bt_addr_to_str(const esp_bd_addr_t bda, char *out);
const char *mgos_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out);

struct esp32_bt_connection {
  esp_gatt_if_t gatt_if;
  esp_bd_addr_t peer_addr;
  uint16_t conn_id;
  uint16_t mtu;
};

struct esp32_bt_session {
  struct esp32_bt_connection *bc;
  void *user_data;
};

typedef bool (*mgos_bt_gatts_handler_t)(struct esp32_bt_session *bs,
                                        esp_gatts_cb_event_t ev,
                                        esp_ble_gatts_cb_param_t *ep);

bool mgos_bt_gatts_register_service(const esp_gatts_attr_db_t *svc_descr,
                                    size_t num_attrs,
                                    mgos_bt_gatts_handler_t cb);

bool esp32_bt_init(void);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_ */
