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

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTS_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTS_H_

#include <stdlib.h>

#include "esp32_bt.h"
#include "esp_gatts_api.h"

#ifdef __cplusplus
extern "C" {
#endif

enum mgos_bt_gatt_perm_level {
  MGOS_BT_GATT_PERM_LEVEL_NONE = 0,
  MGOS_BT_GATT_PERM_LEVEL_ENCR = 1,
  MGOS_BT_GATT_PERM_LEVEL_ENCR_MITM = 2,
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

int mgos_bt_gatts_get_num_connections(void);

/*
 * A drop-in replacement for `esp_ble_gatts_send_indicate()`, but queues
 * requests if some is already in flight.
 */
bool mgos_bt_gatts_send_indicate(esp_gatt_if_t gatts_if, uint16_t conn_id,
                                 uint16_t attr_handle, struct mg_str value,
                                 bool need_confirm);

/*
 * Return whether the send queue (which is used by
 * mgos_bt_gatts_send_indicate) is empty
 */
bool mgos_bt_gatts_is_send_queue_empty(void);

/*
 * Close GATTS connection
 */
bool mgos_bt_gatts_close(esp_gatt_if_t gatts_if, uint16_t conn_id);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTS_H_ */
