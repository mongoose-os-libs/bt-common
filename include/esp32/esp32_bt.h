/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_

#include <stdlib.h>

#include "esp_bt_defs.h"
#include "esp_gatt_defs.h"
#include "esp_gattc_api.h"
#include "esp_gatts_api.h"

#include "common/mg_str.h"

#define BT_ADDR_STR_LEN (ESP_BD_ADDR_LEN * 2 + ESP_BD_ADDR_LEN)
#define BT_UUID_STR_LEN (ESP_UUID_LEN_128 * 2 + ESP_UUID_LEN_128)

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_DEV_NAME_LEN 32

const uint16_t primary_service_uuid;
const uint16_t char_decl_uuid;
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

typedef void (*mgos_bt_gattc_open_cb)(int conn_id, bool result, void *arg);
void mgos_bt_gattc_open_addr(const esp_bd_addr_t addr, int mtu,
                             mgos_bt_gattc_open_cb cb, void *cb_arg);
void mgos_bt_gattc_open_name(const struct mg_str name, int mtu,
                             mgos_bt_gattc_open_cb cb, void *cb_arg);

typedef void (*mgos_bt_gattc_list_services_cb_t)(int conn_id, int num_res,
                                                 const esp_gatt_srvc_id_t *res,
                                                 void *arg);
void mgos_bt_gattc_list_services(int conn_id,
                                 mgos_bt_gattc_list_services_cb_t cb,
                                 void *cb_arg);

struct mgos_bt_gattc_list_chars_result {
  esp_gatt_id_t char_id;
  esp_gatt_char_prop_t char_prop;
};

typedef void (*mgos_bt_gattc_list_chars_cb_t)(
    int conn_id, const esp_gatt_srvc_id_t *svc_id, int num_res,
    const struct mgos_bt_gattc_list_chars_result *res, void *arg);
void mgos_bt_gattc_list_chars(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                              mgos_bt_gattc_list_chars_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_read_char_cb_t)(int conn_id, bool success,
                                             const struct mg_str value,
                                             void *arg);
void mgos_bt_gattc_read_char(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                             const esp_gatt_id_t *char_id,
                             esp_gatt_auth_req_t auth_req,
                             mgos_bt_gattc_read_char_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_write_char_cb_t)(int conn_id, bool success,
                                              void *arg);
void mgos_bt_gattc_write_char(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                              const esp_gatt_id_t *char_id,
                              bool response_required,
                              esp_gatt_auth_req_t auth_req,
                              const struct mg_str value,
                              mgos_bt_gattc_write_char_cb_t cb, void *cb_arg);

void mgos_bt_gattc_close(int conn_id);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_H_ */
