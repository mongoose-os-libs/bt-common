/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#include "mgos_bt.h"

#include <stdio.h>

const char *mgos_bt_addr_to_str(const struct mgos_bt_addr *addr, char *out) {
  sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", addr->addr[0], addr->addr[1],
          addr->addr[2], addr->addr[3], addr->addr[4], addr->addr[5]);
  return out;
}

bool mgos_bt_addr_from_str(const struct mg_str addr_str,
                           struct mgos_bt_addr *addr) {
  unsigned int a[MGOS_BT_ADDR_LEN];
  struct mg_str addr_str_nul = mg_strdup_nul(addr_str);
  bool result = (sscanf(addr_str_nul.p, "%02x:%02x:%02x:%02x:%02x:%02x", &a[0],
                        &a[1], &a[2], &a[3], &a[4], &a[5]) == MGOS_BT_ADDR_LEN);
  if (result) {
    for (int i = 0; i < MGOS_BT_ADDR_LEN; i++) {
      addr->addr[i] = a[i];
    }
  }
  free((void *) addr_str_nul.p);
  return result;
}

int mgos_bt_addr_cmp(const struct mgos_bt_addr *a,
                     const struct mgos_bt_addr *b) {
  return memcmp(a->addr, b->addr, MGOS_BT_ADDR_LEN);
}

bool mgos_bt_addr_is_null(const struct mgos_bt_addr *addr) {
  const struct mgos_bt_addr null_addr = {0};
  return (mgos_bt_addr_cmp(addr, &null_addr) == 0);
}
