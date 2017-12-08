/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_INTERNAL_H_
#define CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_INTERNAL_H_

#include <stdbool.h>

#include "common/cs_dbg.h"

#ifdef __cplusplus
extern "C" {
#endif

enum cs_log_level ll_from_status(esp_bt_status_t status);

bool is_scanning(void);
bool esp32_bt_gattc_init(void);

bool esp32_bt_init(void);
bool esp32_bt_gap_init(void);
bool esp32_bt_gatts_init(void);
void esp32_bt_gatts_auth_cmpl(const esp_bd_addr_t addr);

void esp32_bt_set_is_advertising(bool is_advertising);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_SRC_ESP32_ESP32_BT_INTERNAL_H_ */
