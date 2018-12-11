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

#include "mgos_bt_ble.h"

#ifdef MGOS_HAVE_MJS
#include "mjs.h"
#endif

struct mg_str mgos_bt_ble_parse_adv_data(const struct mg_str adv_data,
                                         enum mgos_bt_ble_eir_type t) {
  const uint8_t *dp = (const uint8_t *) adv_data.p;
  struct mg_str res = MG_NULL_STR;
  for (size_t i = 0; i < adv_data.len;) {
    size_t len = dp[i];
    if (i + len + 1 > adv_data.len) break;
    if (dp[i + 1] == t) {
      res.p = (const char *) dp + i + 2;
      res.len = len - 1;
      break;
    }
    i += len + 1;
  }
  return res;
}

struct mg_str mgos_bt_ble_parse_name(const struct mg_str adv_data) {
  struct mg_str s =
      mgos_bt_ble_parse_adv_data(adv_data, MGOS_BT_BLE_EIR_FULL_NAME);
  if (s.len == 0) {
    s = mgos_bt_ble_parse_adv_data(adv_data, MGOS_BT_BLE_EIR_SHORT_NAME);
  }
  return s;
}

/* FFI helpers */
#ifdef MGOS_HAVE_MJS
bool mgos_bt_ble_scan_js(int duration_ms, bool active) {
  struct mgos_bt_ble_scan_opts opts = {
      .duration_ms = duration_ms, .active = active,
  };
  return mgos_bt_ble_scan(&opts);
}

mjs_val_t bt_addr_to_obj(struct mjs *mjs, void *ap) {
  const struct mgos_bt_addr *addr = (const struct mgos_bt_addr *) ap;
  char as[MGOS_BT_ADDR_STR_LEN];
  mgos_bt_addr_to_str(addr, 0, as);
  mjs_val_t val = mjs_mk_object(mjs);
  mjs_own(mjs, &val); /* Pin the object while it is being built */
  mjs_set(mjs, val, "type", 4, mjs_mk_number(mjs, addr->type));
  mjs_set(mjs, val, "addr", 4, mjs_mk_string(mjs, as, ~0, 1));
  mjs_disown(mjs, &val);
  return val;
}

/* Struct descriptor for use with s2o() */
static const struct mjs_c_struct_member srdd[] = {
    {"advData", offsetof(struct mgos_bt_ble_scan_result, adv_data),
     MJS_STRUCT_FIELD_TYPE_MG_STR, NULL},
    {"scanRsp", offsetof(struct mgos_bt_ble_scan_result, scan_rsp),
     MJS_STRUCT_FIELD_TYPE_MG_STR, NULL},
    {"rssi", offsetof(struct mgos_bt_ble_scan_result, rssi),
     MJS_STRUCT_FIELD_TYPE_INT, NULL},
    {"addr", offsetof(struct mgos_bt_ble_scan_result, addr),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_addr_to_obj},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_ble_get_srdd(void) {
  return srdd;
}
#endif /* HAVE_MJS */
