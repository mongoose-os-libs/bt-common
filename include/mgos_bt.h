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

#define MGOS_BT_ADDR_LEN 6
struct mgos_bt_addr {
  uint8_t addr[MGOS_BT_ADDR_LEN];
};

#define BT_ADDR_STR_LEN (MGOS_BT_ADDR_LEN * 2 + MGOS_BT_ADDR_LEN)

const char *mgos_bt_addr_to_str(const struct mgos_bt_addr *addr, char *out);
bool mgos_bt_addr_from_str(const struct mg_str addr_str,
                           struct mgos_bt_addr *addr);
int mgos_bt_addr_cmp(const struct mgos_bt_addr *a,
                     const struct mgos_bt_addr *b);
bool mgos_bt_addr_is_null(const struct mgos_bt_addr *addr);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BT_COMMON_INCLUDE_MGOS_BT_H_ */
