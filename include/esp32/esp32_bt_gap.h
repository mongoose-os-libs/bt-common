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

#include "mgos_bt_gap.h"

#include "esp32_bt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_GAP_DEFAULT_SCAN_WINDOW_MS 50
#define MGOS_BT_GAP_DEFAULT_SCAN_INTERVAL_MS 100
#define MGOS_BT_GAP_DEFAULT_SCAN_DURATION_MS 5000

#define MGOS_BT_GAP_MAX_SCAN_RSP_DATA_LEN 31

bool mgos_bt_gap_get_pairing_enable(void);
bool mgos_bt_gap_set_pairing_enable(bool pairing_enable);

#ifdef __cplusplus
}
#endif
