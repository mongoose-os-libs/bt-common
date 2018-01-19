/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MOS_LIBS_BT_GAP_H
#define MOS_LIBS_BT_GAP_H

#include "mgos_bt.h"
#include "mgos_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_GAP_ADV_DATA_LEN 31

#define MGOS_BT_GAP_EVENT_BASE MGOS_EVENT_BASE('G', 'A', 'P')

enum mgos_bt_gap_event {
  MGOS_BT_GAP_EVENT_SCAN_RESULT =
      MGOS_BT_GAP_EVENT_BASE,  /* mgos_gap_scan_result */
  MGOS_BT_GAP_EVENT_SCAN_STOP, /* NULL */
};

struct mgos_bt_gap_scan_opts {
  int duration_ms;
};

// https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile
enum mgos_bt_gap_eir_type {
  MGOS_BT_GAP_EIR_FLAGS = 0x1,
  MGOS_BT_GAP_EIR_SHORT_NAME = 0x8,
  MGOS_BT_GAP_EIR_FULL_NAME = 0x9,
  MGOS_BT_GAP_EIR_DEVICE_ID = 0x10,
  MGOS_BT_GAP_EIR_URL = 0x24,
  MGOS_BT_GAP_EIR_MANUFACTURER_SPECIFIC_DATA = 0xff,
};

struct mg_str mgos_bt_gap_parse_adv_data(const uint8_t *data,
                                         enum mgos_bt_gap_eir_type);

struct mgos_bt_gap_scan_result {
  uint8_t adv_data[MGOS_BT_GAP_ADV_DATA_LEN];
  uint8_t scan_rsp[MGOS_BT_GAP_ADV_DATA_LEN];
  struct mgos_bt_addr addr; /* MAC address. Can change randomly. */
  int rssi;                 /* Signal strength indicator. */
};

bool mgos_bt_gap_scan(const struct mgos_bt_gap_scan_opts *);

#ifdef __cplusplus
}
#endif

#endif /* MOS_LIBS_GAP_H */
