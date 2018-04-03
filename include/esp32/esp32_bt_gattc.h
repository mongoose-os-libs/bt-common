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
  struct mgos_bt_uuid char_id;
  esp_gatt_char_prop_t char_prop;
};

typedef void (*mgos_bt_gattc_list_chars_cb_t)(
    int conn_id, const struct mgos_bt_uuid *svc_id, int num_res,
    const struct mgos_bt_gattc_list_chars_result *res, void *arg);
void mgos_bt_gattc_list_chars(int conn_id, const struct mgos_bt_uuid *svc_id,
                              mgos_bt_gattc_list_chars_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_read_char_cb_t)(int conn_id, bool success,
                                             const struct mg_str value,
                                             void *arg);
void mgos_bt_gattc_read_char(int conn_id, const struct mgos_bt_uuid *svc_uuid,
                             const struct mgos_bt_uuid *char_uuid,
                             esp_gatt_auth_req_t auth_req,
                             mgos_bt_gattc_read_char_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_write_char_cb_t)(int conn_id, bool success,
                                              void *arg);
void mgos_bt_gattc_write_char(int conn_id, const struct mgos_bt_uuid *svc_uuid,
                              const struct mgos_bt_uuid *char_uuid,
                              bool response_required,
                              esp_gatt_auth_req_t auth_req,
                              const struct mg_str value,
                              mgos_bt_gattc_write_char_cb_t cb, void *cb_arg);

typedef void (*mgos_bt_gattc_subscribe_cb_t)(int conn_id, bool success,
                                             const struct mg_str value,
                                             void *arg);
void esp32_gattc_subscribe(int conn_id, const struct mgos_bt_uuid *svc_uuid,
                           const struct mgos_bt_uuid *char_uuid,
                           mgos_bt_gattc_subscribe_cb_t cb, void *cb_arg);

void mgos_bt_gattc_close(int conn_id);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTC_H_ */
