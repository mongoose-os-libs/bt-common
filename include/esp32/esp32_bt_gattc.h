/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTC_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTC_H_

#include <stdlib.h>

#include "esp32_bt.h"
#include "esp_gattc_api.h"

#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mgos_bt_gattc_open_cb)(int conn_id, bool result, void *arg);
void mgos_bt_gattc_open_addr(const struct mgos_bt_addr *addr,
                             mgos_bt_gattc_open_cb cb, void *cb_arg);
void mgos_bt_gattc_open_name(const struct mg_str name, mgos_bt_gattc_open_cb cb,
                             void *cb_arg);

bool mgos_bt_gattc_get_conn_info(int conn_id, struct esp32_bt_connection *bc);

typedef void (*mgos_bt_gattc_list_services_cb_t)(int conn_id, int num_res,
                                                 const esp_gatt_srvc_id_t *res,
                                                 void *arg);
void mgos_bt_gattc_list_services(int conn_id,
                                 mgos_bt_gattc_list_services_cb_t cb,
                                 void *cb_arg);

struct mgos_bt_gattc_list_chars_result {
  esp_bt_uuid_t char_id;
  esp_gatt_char_prop_t char_prop;
};

typedef void (*mgos_bt_gattc_list_chars_cb_t)(
    int conn_id, const esp_bt_uuid_t *svc_id, int num_res,
    const struct mgos_bt_gattc_list_chars_result *res, void *arg);
void mgos_bt_gattc_list_chars(int conn_id, const esp_bt_uuid_t *svc_id,
                              mgos_bt_gattc_list_chars_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_read_char_cb_t)(int conn_id, bool success,
                                             const struct mg_str value,
                                             void *arg);
void mgos_bt_gattc_read_char(int conn_id, const esp_bt_uuid_t *svc_uuid,
                             const esp_bt_uuid_t *char_uuid,
                             esp_gatt_auth_req_t auth_req,
                             mgos_bt_gattc_read_char_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_write_char_cb_t)(int conn_id, bool success,
                                              void *arg);
void mgos_bt_gattc_write_char(int conn_id, const esp_bt_uuid_t *svc_uuid,
                              const esp_bt_uuid_t *char_uuid,
                              bool response_required,
                              esp_gatt_auth_req_t auth_req,
                              const struct mg_str value,
                              mgos_bt_gattc_write_char_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_subscribe_cb_t)(int conn_id, bool success,
                                             const struct mg_str value,
                                             void *arg);
void mgos_bt_gattc_subscribe(int conn_id, const esp_bt_uuid_t *svc_uuid,
                             const esp_bt_uuid_t *char_uuid,
                             mgos_bt_gattc_subscribe_cb_t cb, void *cb_arg);

void mgos_bt_gattc_close(int conn_id);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTC_H_ */
