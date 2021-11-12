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

#include <stdbool.h>
#include <stdint.h>

#include "common/mg_str.h"
#include "mgos_event.h"

#ifdef __cplusplus
extern "C" {
#endif

enum mgos_bt_addr_type {
  MGOS_BT_ADDR_TYPE_NONE = 0,
  MGOS_BT_ADDR_TYPE_PUBLIC = 1,
  MGOS_BT_ADDR_TYPE_RANDOM_STATIC = 2,
  MGOS_BT_ADDR_TYPE_RANDOM_NON_RESOLVABLE = 3,
  MGOS_BT_ADDR_TYPE_RANDOM_RESOLVABLE = 4,
};

struct mgos_bt_addr {
  uint8_t addr[6];
  enum mgos_bt_addr_type type;
};

struct mgos_bt_uuid {
  union {
    uint16_t uuid16;
    uint32_t uuid32;
    uint8_t uuid128[16];
  } uuid;
  uint8_t len;
};

/* Each byte is transformed into 3 bytes: "XX:", and last byte into "XX\0" */
#define MGOS_BT_ADDR_STR_LEN (sizeof(struct mgos_bt_addr) * 3 + 2 /* type */)
#define MGOS_BT_UUID_STR_LEN (sizeof(struct mgos_bt_uuid) * 3)
#define MGOS_BT_DEV_NAME_LEN 32

#define BT_ADDR_STR_LEN MGOS_BT_ADDR_STR_LEN

#define MGOS_BT_ADDR_STRINGIFY_TYPE 1
const char *mgos_bt_addr_to_str(const struct mgos_bt_addr *addr, uint32_t flags,
                                char *out);
bool mgos_bt_addr_from_str(const struct mg_str addr_str,
                           struct mgos_bt_addr *addr);
int mgos_bt_addr_cmp(const struct mgos_bt_addr *a,
                     const struct mgos_bt_addr *b);
bool mgos_bt_addr_is_null(const struct mgos_bt_addr *addr);

const char *mgos_bt_uuid_to_str(const struct mgos_bt_uuid *uuid, char *out);
bool mgos_bt_uuid_from_str(const struct mg_str str, struct mgos_bt_uuid *uuid);
bool mgos_bt_uuid_eq(const struct mgos_bt_uuid *a,
                     const struct mgos_bt_uuid *b);
int mgos_bt_uuid_cmp(const struct mgos_bt_uuid *a,
                     const struct mgos_bt_uuid *b);
void mgos_bt_uuid128_from_bytes(const uint8_t *bytes, bool reverse,
                                struct mgos_bt_uuid *uuid);

void mgos_event_trigger_schedule(int ev, void *ev_data, size_t data_len);

bool mgos_bt_get_device_address(struct mgos_bt_addr *addr);

#ifdef __cplusplus
}
#endif
