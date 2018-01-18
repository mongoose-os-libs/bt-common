/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_BT_COMMON_INCLUDE_MGOS_BT_H_
#define CS_MOS_LIBS_BT_COMMON_INCLUDE_MGOS_BT_H_

#include <stdbool.h>
#include <stdint.h>

#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mgos_bt_addr {
  uint8_t addr[6];
};

/* Binary-equivalent to the ESP32 esp_bt_uuid_t */
struct mgos_bt_uuid {
  uint16_t len;
  union {
    uint16_t uuid16;
    uint32_t uuid32;
    uint8_t uuid128[16];
  } uuid;
} __attribute__((packed));

/* Each byte is transformed into 3 bytes: "XX:", and last byte into "XX\0" */
#define MGOS_BT_ADDR_STR_LEN (sizeof(struct mgos_bt_addr) * 3)
#define MGOS_BT_UUID_STR_LEN (sizeof(struct mgos_bt_uuid) * 3)
#define MGOS_BT_DEV_NAME_LEN 32

#define BT_ADDR_STR_LEN MGOS_BT_ADDR_STR_LEN

const char *mgos_bt_addr_to_str(const struct mgos_bt_addr *addr, char *out);
bool mgos_bt_addr_from_str(const struct mg_str addr_str,
                           struct mgos_bt_addr *addr);
int mgos_bt_addr_cmp(const struct mgos_bt_addr *a,
                     const struct mgos_bt_addr *b);
bool mgos_bt_addr_is_null(const struct mgos_bt_addr *addr);

const char *mgos_bt_uuid_to_str(const struct mgos_bt_uuid *uuid, char *out);
bool mgos_bt_uuid_from_str(const struct mg_str str, struct mgos_bt_uuid *uuid);
int mgos_bt_uuid_cmp(const struct mgos_bt_uuid *a,
                     const struct mgos_bt_uuid *b);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_COMMON_INCLUDE_MGOS_BT_H_ */
