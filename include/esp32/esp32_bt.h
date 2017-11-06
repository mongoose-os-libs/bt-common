/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_

#include <stdlib.h>

#include "esp_bt_defs.h"
#include "esp_gatt_defs.h"

#include "common/mg_str.h"

#define BT_ADDR_STR_LEN (ESP_BD_ADDR_LEN * 2 + ESP_BD_ADDR_LEN)
#define BT_UUID_STR_LEN (ESP_UUID_LEN_128 * 2 + ESP_UUID_LEN_128)

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_DEV_NAME_LEN 32

const uint16_t primary_service_uuid;
const uint16_t char_decl_uuid;
const uint16_t char_client_config_uuid;
const uint8_t char_prop_read_write;
const uint8_t char_prop_read_notify;
const uint8_t char_prop_write;

const char *mgos_bt_addr_to_str(const esp_bd_addr_t addr, char *out);
bool mgos_bt_addr_from_str(const struct mg_str addr_str, esp_bd_addr_t addr);
int mgos_bt_addr_cmp(const esp_bd_addr_t a, const esp_bd_addr_t b);
bool mgos_bt_addr_is_null(const esp_bd_addr_t a);

const char *mgos_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out);
bool mgos_bt_uuid_from_str(const struct mg_str uuid_str, esp_bt_uuid_t *uuid);
int mgos_bt_uuid_cmp(const esp_bt_uuid_t *a, const esp_bt_uuid_t *b);

struct esp32_bt_connection {
  esp_gatt_if_t gatt_if;
  esp_bd_addr_t peer_addr;
  uint16_t conn_id;
  uint16_t mtu;
};

struct mgos_bt_ble_scan_result {
  esp_bd_addr_t addr;
  char name[MGOS_BT_DEV_NAME_LEN + 1]; /* NUL-terminated */
  int rssi;
};
typedef void (*mgos_bt_ble_scan_cb_t)(int num_res,
                                      const struct mgos_bt_ble_scan_result *res,
                                      void *arg);
void mgos_bt_ble_scan(mgos_bt_ble_scan_cb_t cb, void *cb_arg);
void mgos_bt_ble_scan_device_addr(const esp_bd_addr_t addr,
                                  mgos_bt_ble_scan_cb_t cb, void *cb_arg);
void mgos_bt_ble_scan_device_name(const struct mg_str name,
                                  mgos_bt_ble_scan_cb_t cb, void *cb_arg);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_ */
