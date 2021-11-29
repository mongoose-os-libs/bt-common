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

#include "mgos_bt.h"

#include "host/ble_uuid.h"
#include "nimble/ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_ADDR_LEN 6

void mgos_bt_addr_to_esp32(const struct mgos_bt_addr *in, ble_addr_t *out);
void esp32_bt_addr_to_mgos(const ble_addr_t *in, struct mgos_bt_addr *out);
const char *esp32_bt_addr_to_str(const ble_addr_t *addr, char *out);

void mgos_bt_uuid_to_esp32(const struct mgos_bt_uuid *in, ble_uuid_any_t *out);
void esp32_bt_uuid_to_mgos(const ble_uuid_t *in, struct mgos_bt_uuid *out);
const char *esp32_bt_uuid_to_str(const ble_uuid_t *uuid, char *out);

#ifdef __cplusplus
}
#endif
