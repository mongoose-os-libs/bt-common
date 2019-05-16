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

#include "mgos_bt_gap.h"

#include <string.h>

#ifdef MGOS_HAVE_MJS
#include "mjs.h"
#endif

struct mg_str mgos_bt_gap_parse_adv_data(struct mg_str adv_data,
                                         enum mgos_bt_gap_eir_type t) {
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

struct mg_str mgos_bt_gap_parse_name(struct mg_str adv_data) {
  struct mg_str s =
      mgos_bt_gap_parse_adv_data(adv_data, MGOS_BT_GAP_EIR_FULL_NAME);
  if (s.len == 0) {
    s = mgos_bt_gap_parse_adv_data(adv_data, MGOS_BT_GAP_EIR_SHORT_NAME);
  }
  return s;
}

struct mg_str mgos_bt_gap_parse_service_data(struct mg_str adv_data,
                                             const struct mgos_bt_uuid *svc_uuid) {
  enum mgos_bt_gap_eir_type et;
  switch (svc_uuid->len) {
    case sizeof(svc_uuid->uuid.uuid16):
      et = MGOS_BT_GAP_EIR_SERVICE_DATA_16;
      break;
    case sizeof(svc_uuid->uuid.uuid32):
      et = MGOS_BT_GAP_EIR_SERVICE_DATA_32;
      break;
    case sizeof(svc_uuid->uuid.uuid128):
      et = MGOS_BT_GAP_EIR_SERVICE_DATA_128;
      break;
    default:
      goto out;
  }
  while (adv_data.len > 0) {
    struct mg_str svc_data = mgos_bt_gap_parse_adv_data(adv_data, et);
    if (svc_data.len < svc_uuid->len) break;
    if (memcmp(svc_data.p, &svc_uuid->uuid, svc_uuid->len) == 0) {
      return mg_mk_str_n(svc_data.p + svc_uuid->len, svc_data.len - svc_uuid->len);
    }
    svc_data.p += svc_data.len;
    adv_data.len = adv_data.len - (svc_data.p - adv_data.p);
    adv_data.p = svc_data.p;
  }
out:
  return mg_mk_str_n(NULL, 0);
}
