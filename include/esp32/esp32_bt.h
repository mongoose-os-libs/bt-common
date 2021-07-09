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

#pragma once

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

const char *esp32_bt_addr_to_str(const esp_bd_addr_t addr, char *out);
int esp32_bt_addr_cmp(const esp_bd_addr_t a, const esp_bd_addr_t b);
const char *esp32_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out);

void mgos_bt_uuid_to_esp32(const struct mgos_bt_uuid *in, esp_bt_uuid_t *out);
void esp32_bt_uuid_to_mgos(const esp_bt_uuid_t *in, struct mgos_bt_uuid *out);

#ifdef __cplusplus
}
#endif
