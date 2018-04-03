/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_

#include <stdlib.h>

#include "esp_bt_defs.h"
#include "esp_gatt_defs.h"

#include "common/mg_str.h"

#include "mgos_bt.h"

#define MGOS_BT_DEV_NAME_LEN 32
#define BT_UUID_STR_LEN (ESP_UUID_LEN_128 * 2 + ESP_UUID_LEN_128)

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_ADDR_LEN 6

const uint16_t primary_service_uuid;
const uint16_t char_decl_uuid;
const uint16_t char_client_config_uuid;
const uint8_t char_prop_read;
const uint8_t char_prop_read_notify;
const uint8_t char_prop_read_write;
const uint8_t char_prop_read_write_notify;
const uint8_t char_prop_write;

const char *esp32_bt_addr_to_str(const esp_bd_addr_t addr, char *out);
bool esp32_bt_addr_from_str(const struct mg_str addr_str, esp_bd_addr_t addr);
int esp32_bt_addr_cmp(const esp_bd_addr_t a, const esp_bd_addr_t b);
bool esp32_bt_addr_is_null(const esp_bd_addr_t addr);

const char *esp32_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out);
bool esp32_bt_uuid_from_str(const struct mg_str uuid_str, esp_bt_uuid_t *uuid);
int esp32_bt_uuid_cmp(const esp_bt_uuid_t *a, const esp_bt_uuid_t *b);

struct esp32_bt_connection {
  esp_gatt_if_t gatt_if;
  struct mgos_bt_addr peer_addr;
  uint16_t conn_id;
  uint16_t mtu;
};

/* Scan each channel for 50 ms, change channel every 100 ms; for 5 seconds */
#define MGOS_BT_BLE_DEFAULT_SCAN_WINDOW_MS 50
#define MGOS_BT_BLE_DEFAULT_SCAN_INTERVAL_MS 100
#define MGOS_BT_BLE_DEFAULT_SCAN_DURATION_MS 5000
struct mgos_bt_ble_scan_opts {
  bool active;
  int window_ms;
  int interval_ms;
  int duration_ms;
  esp_bd_addr_t addr;
  struct mg_str name;
};
struct mgos_bt_ble_scan_result {
  struct mgos_bt_addr addr;
  struct mg_str adv_data; /* Raw adv data */
  struct mg_str scan_rsp; /* Raw scan response (for active scans) */
  char name[MGOS_BT_DEV_NAME_LEN + 1]; /* NUL-terminated */
  int rssi;
};
typedef void (*mgos_bt_ble_scan_cb_t)(int num_res,
                                      const struct mgos_bt_ble_scan_result *res,
                                      void *arg);
void mgos_bt_ble_scan(const struct mgos_bt_ble_scan_opts *opts,
                      mgos_bt_ble_scan_cb_t cb, void *cb_arg);

#define MGOS_BT_BLE_MAX_SCAN_RSP_DATA_LEN 31
void mgos_bt_ble_set_scan_rsp_data(const struct mg_str scan_rsp_data);

bool mgos_bt_gap_get_adv_enable(void);
bool mgos_bt_gap_set_adv_enable(bool adv_enable);

bool mgos_bt_gap_get_pairing_enable(void);
bool mgos_bt_gap_set_pairing_enable(bool pairing_enable);

int mgos_bt_ble_get_num_paired_devices(void);
/*
 * These are actually async. TODO(rojer): Add callbacks to the API.
 * For now, just allow some time for the calls to complete.
 */
void mgos_bt_ble_remove_paired_device(const esp_bd_addr_t addr);
void mgos_bt_ble_remove_all_paired_devices(void);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_ */
