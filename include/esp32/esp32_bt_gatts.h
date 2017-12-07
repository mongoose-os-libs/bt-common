/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
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

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_GATTS_H_ */