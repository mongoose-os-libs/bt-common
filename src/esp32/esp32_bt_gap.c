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

#include "esp32_bt_gap.h"

#include "mgos.h"

#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"

#include "esp32_bt_internal.h"

static bool s_adv_enable = false;
static bool s_advertising = false;
static struct mg_str s_adv_data = MG_NULL_STR;
static struct mg_str s_scan_rsp_data = MG_NULL_STR;

bool mgos_bt_gap_get_pairing_enable(void) {
  return ble_hs_cfg.sm_bonding;
}

int mgos_bt_gap_get_num_paired_devices(void) {
  int count = 0;
  ble_store_util_count(BLE_STORE_OBJ_TYPE_OUR_SEC, &count);
  return count;
}

void mgos_bt_gap_remove_paired_device(const struct mgos_bt_addr *addr) {
  ble_addr_t baddr;
  mgos_bt_addr_to_esp32(addr, &baddr);
  ble_gap_unpair(&baddr);
}

void mgos_bt_gap_remove_all_paired_devices(void) {
  ble_store_clear();
}

struct mgos_bt_scan_result_entry {
  int64_t ts;
  struct mgos_bt_gap_scan_result arg;
  SLIST_ENTRY(mgos_bt_scan_result_entry) next;
};
SLIST_HEAD(mgos_bt_scan_result_list, mgos_bt_scan_result_entry);
struct mgos_bt_scan_ctx {
  bool active;
  struct mgos_bt_scan_result_list results;
};

#define SCAN_RSP_WAIT_MICROS 1000000

static void check_pending_results(struct mgos_bt_scan_ctx *ctx, int64_t now,
                                  const struct mgos_bt_addr *addr,
                                  const struct mg_str *scan_rsp) {
  if (SLIST_EMPTY(&ctx->results)) return;
  struct mgos_bt_scan_result_entry *re = NULL, *ret = NULL;
  SLIST_FOREACH_SAFE(re, &ctx->results, next, ret) {
    if (addr != NULL && mgos_bt_addr_cmp(&re->arg.addr, addr) == 0) {
      re->arg.scan_rsp = mg_strdup(*scan_rsp);
    } else if (now - re->ts < SCAN_RSP_WAIT_MICROS) {
      continue;
    }
    SLIST_REMOVE(&ctx->results, re, mgos_bt_scan_result_entry, next);
    mgos_event_trigger_schedule(MGOS_BT_GAP_EVENT_SCAN_RESULT, &re->arg,
                                sizeof(re->arg));
    free(re);
  }
}

static int mgos_bt_scan_event_fn(struct ble_gap_event *ev, void *arg) {
  struct mgos_bt_scan_ctx *ctx = arg;
  switch (ev->type) {
    case BLE_GAP_EVENT_DISC: {
      uint8_t evt = ev->disc.event_type;
      char addr[MGOS_BT_ADDR_STR_LEN];
      struct mgos_bt_gap_scan_result arg = {
          .rssi = ev->disc.rssi,
      };
      esp32_bt_addr_to_mgos(&ev->disc.addr, &arg.addr);
      struct mg_str data =
          mg_mk_str_n((char *) ev->disc.data, ev->disc.length_data);
      LOG(LL_DEBUG,
          ("DEVT %d addr %s rssi %d dl %d", evt,
           mgos_bt_addr_to_str(&arg.addr, MGOS_BT_ADDR_STRINGIFY_TYPE, addr),
           arg.rssi, ev->disc.length_data));
      if (!ctx->active || evt == BLE_HCI_ADV_RPT_EVTYPE_NONCONN_IND) {
        if (evt == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND ||
            evt == BLE_HCI_ADV_RPT_EVTYPE_NONCONN_IND) {
          arg.adv_data = mg_strdup(data);
          mgos_event_trigger_schedule(MGOS_BT_GAP_EVENT_SCAN_RESULT, &arg,
                                      sizeof(arg));
        }
        break;
      }
      // Active scan delivers advertising data first, then scan response.
      // We need to wait until that event arrives before delivering ours.
      if (ev->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND) {
        struct mgos_bt_scan_result_entry *re = NULL;
        SLIST_FOREACH(re, &ctx->results, next) {
          if (mgos_bt_addr_cmp(&re->arg.addr, &arg.addr) == 0) break;
        }
        if (re == NULL) {
          re = calloc(1, sizeof(*re));
          if (re == NULL) {
            mg_strfree(&arg.adv_data);
            break;
          }
          SLIST_INSERT_HEAD(&ctx->results, re, next);
        } else {
          mg_strfree(&re->arg.adv_data);
        }
        re->ts = mgos_uptime_micros();
        re->arg = arg;
        re->arg.adv_data = mg_strdup(data);
      } else if (ev->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP) {
        check_pending_results(ctx, mgos_uptime_micros(), &arg.addr, &data);
      } else {
        check_pending_results(ctx, mgos_uptime_micros(), NULL, NULL);
      }
      break;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE: {
      LOG(LL_DEBUG, ("DISC_COMPLETE"));
      // Flush the pending result list.
      check_pending_results(ctx, mgos_uptime_micros() + SCAN_RSP_WAIT_MICROS,
                            NULL, NULL);
      mgos_event_trigger_schedule(MGOS_BT_GAP_EVENT_SCAN_STOP, NULL, 0);
      free(ctx);
      break;
    }
  }
  return 0;
  (void) arg;
}

bool mgos_bt_gap_scan(const struct mgos_bt_gap_scan_opts *opts) {
  struct mgos_bt_scan_ctx *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) return false;
  struct ble_gap_disc_params params = {
      .itvl = MGOS_BT_GAP_DEFAULT_SCAN_INTERVAL_MS / 0.625,
      .window = MGOS_BT_GAP_DEFAULT_SCAN_WINDOW_MS / 0.625,
      .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
      .limited = false,
      .passive = !opts->active,
      .filter_duplicates = false,
  };
  ctx->active = opts->active;
  SLIST_INIT(&ctx->results);
  int rc = ble_gap_disc(own_addr_type, opts->duration_ms, &params,
                        mgos_bt_scan_event_fn, ctx);
  if (rc == 0) {
    LOG(LL_DEBUG, ("Starting scan (%s, %d ms %d/%d w/i)",
                   (params.passive ? "passive" : "active"), opts->duration_ms,
                   params.window, params.itvl));
    return true;
  } else {
    LOG(LL_ERROR, ("Failed to start scan (%d)", rc));
    free(ctx);
    return false;
  }
}

static int esp32_bt_gap_event(struct ble_gap_event *ev, void *arg) {
  int ret = 0;
  LOG(LL_DEBUG, ("GAP Event %d", ev->type));
  esp32_bt_rlock();
  switch (ev->type) {
    // Forward GATTS events to the GATTS handler.
    case BLE_GAP_EVENT_CONNECT:
      // Connect disables advertising. Resume, if it's enabled.
      s_advertising = false;
      esp32_bt_gap_start_advertising();
      // fallthrough
    case BLE_GAP_EVENT_DISCONNECT:
    case BLE_GAP_EVENT_ENC_CHANGE:
    case BLE_GAP_EVENT_SUBSCRIBE:
    case BLE_GAP_EVENT_NOTIFY_TX:
    case BLE_GAP_EVENT_MTU:
      ret = esp32_bt_gatts_event(ev, arg);
      break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
      s_advertising = false;
      esp32_bt_gap_start_advertising();
      break;
    case BLE_GAP_EVENT_PASSKEY_ACTION:
      // TODO
      break;
    case BLE_GAP_EVENT_REPEAT_PAIRING: {
      // We already have a bond with the peer, but it is attempting to
      // establish a new secure link.  This app sacrifices security for
      // convenience: just throw away the old bond and accept the new link.
      struct ble_gap_conn_desc desc;
      if (ble_gap_conn_find(ev->repeat_pairing.conn_handle, &desc) == 0) {
        ble_store_util_delete_peer(&desc.peer_id_addr);
      }
      // Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
      // continue with the pairing operation.
      ret = BLE_GAP_REPEAT_PAIRING_RETRY;
    }
  }
  esp32_bt_runlock();
  return ret;
}

bool esp32_bt_gap_start_advertising(void) {
  int rc;

  if (s_advertising) return true;
  if (!s_adv_enable) return false;
  if (!ble_hs_synced()) return false;
  const char *dev_name = mgos_sys_config_get_bt_dev_name();
  if (dev_name == NULL) {
    dev_name = mgos_sys_config_get_device_id();
  }
  if (dev_name == NULL) {
    LOG(LL_ERROR, ("bt.dev_name or device.id must be set"));
    return false;
  }
  if (ble_svc_gap_device_name_set(dev_name) != 0) {
    return false;
  }
  if (s_adv_data.len > 0) {
    if ((rc = ble_gap_adv_set_data((const uint8_t *) s_adv_data.p,
                                   s_adv_data.len)) != 0) {
      LOG(LL_ERROR, ("ble_gap_adv_set_data: %d", rc));
      return false;
    }
  } else {
    struct ble_hs_adv_fields fields = {
        .flags = 0,
        .name = (uint8_t *) dev_name,
        .name_len = strlen(dev_name),
        .name_is_complete = true,
    };
    if ((rc = ble_gap_adv_set_fields(&fields)) != 0) {
      LOG(LL_ERROR, ("ble_gap_adv_set_fields: %d", rc));
      return false;
    }
  }
  if (s_scan_rsp_data.len > 0) {
    if ((rc = ble_gap_adv_rsp_set_data((const uint8_t *) s_scan_rsp_data.p,
                                       s_scan_rsp_data.len)) != 0) {
      LOG(LL_ERROR, ("ble_gap_adv_rsp_set_data: %d", rc));
      return false;
    }
  } else {
    struct mg_str scan_rsp_data_hex =
        mg_mk_str(mgos_sys_config_get_bt_scan_rsp_data_hex());
    if (scan_rsp_data_hex.len > 0) {
      struct mg_str scan_rsp_data = MG_NULL_STR;
      json_scanf(scan_rsp_data_hex.p, scan_rsp_data_hex.len, "%H",
                 &scan_rsp_data.len, &scan_rsp_data.p);
      if (scan_rsp_data.len > 0) {
        if (scan_rsp_data.len <= MGOS_BT_GAP_MAX_SCAN_RSP_DATA_LEN) {
          mgos_bt_gap_set_scan_rsp_data(scan_rsp_data);
        } else {
          LOG(LL_ERROR, ("Scan response data too long (%d), max is %d",
                         scan_rsp_data.len, MGOS_BT_GAP_MAX_SCAN_RSP_DATA_LEN));
        }
      }
      mg_strfree(&scan_rsp_data);
    }
  }
  if ((rc = ble_hs_id_infer_auto(0, &own_addr_type)) != 0) {
    LOG(LL_ERROR, ("ble_hs_id_infer_auto: %d", rc));
    return false;
  }
  struct ble_gap_adv_params adv_params = {
      .conn_mode = BLE_GAP_CONN_MODE_UND,
      .disc_mode = BLE_GAP_DISC_MODE_GEN,
      .itvl_min = BLE_GAP_ADV_FAST_INTERVAL2_MIN,
      .itvl_max = BLE_GAP_ADV_FAST_INTERVAL2_MAX,
      .channel_map = BLE_GAP_ADV_DFLT_CHANNEL_MAP,
  };
  if ((rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &adv_params,
                              esp32_bt_gap_event, NULL)) != 0) {
    LOG(LL_ERROR, ("ble_gap_adv_start: %d", rc));
    return false;
  }
  s_advertising = true;
  struct mgos_bt_addr addr;
  if (mgos_bt_get_device_address(&addr)) {
    char addr_str[MGOS_BT_ADDR_STR_LEN] = {0};
    LOG(LL_INFO,
        ("Advertising name %s, addr %s", dev_name,
         mgos_bt_addr_to_str(&addr, MGOS_BT_ADDR_STRINGIFY_TYPE, addr_str)));
  }
  return true;
}

static bool esp32_bt_gap_stop_advertising(void) {
  esp32_bt_rlock();
  bool res = !s_advertising;
  if (res) goto out;
  res = (ble_gap_adv_stop() == 0);
  if (res) s_advertising = false;
out:
  esp32_bt_runlock();
  return res;
}

bool mgos_bt_gap_get_adv_enable(void) {
  return s_adv_enable;
}

bool mgos_bt_gap_set_adv_data(struct mg_str adv_data) {
  if (mg_strcmp(adv_data, s_adv_data) == 0) return true;
  mg_strfree(&s_adv_data);
  s_adv_data = mg_strdup(adv_data);
  return (ble_gap_adv_set_data((const uint8_t *) s_adv_data.p,
                               s_adv_data.len) == 0);
}

bool mgos_bt_gap_set_scan_rsp_data(struct mg_str scan_rsp_data) {
  if (mg_strcmp(scan_rsp_data, s_scan_rsp_data) == 0) return true;
  mg_strfree(&s_scan_rsp_data);
  s_scan_rsp_data = mg_strdup(scan_rsp_data);
  return (ble_gap_adv_rsp_set_data((const uint8_t *) s_scan_rsp_data.p,
                                   s_scan_rsp_data.len) == 0);
}

bool mgos_bt_gap_set_adv_enable(bool adv_enable) {
  esp32_bt_rlock();
  s_adv_enable = adv_enable;
  bool res = (s_adv_enable ? esp32_bt_gap_start_advertising()
                           : esp32_bt_gap_stop_advertising());
  esp32_bt_rlock();
  return res;
}
