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
  LOG(LL_DEBUG, ("GAP Event %d", ev->type));
  switch (ev->type) {
    // Forward GATTS events to the GATTS handler.
    case BLE_GAP_EVENT_CONNECT:
      // Connect disables advertising. Resume, if it's enabled.
      s_advertising = false;
      mgos_bt_gap_set_adv_enable(mgos_bt_gap_get_adv_enable());
      // fallthrough
    case BLE_GAP_EVENT_DISCONNECT:
    case BLE_GAP_EVENT_CONN_UPDATE:
    case BLE_GAP_EVENT_ENC_CHANGE:
    case BLE_GAP_EVENT_SUBSCRIBE:
    case BLE_GAP_EVENT_MTU:
    case BLE_GAP_EVENT_NOTIFY_TX:
      esp32_bt_gatts_event(ev, arg);
      break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
      s_advertising = false;
      mgos_bt_gap_set_adv_enable(mgos_bt_gap_get_adv_enable());
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
      return BLE_GAP_REPEAT_PAIRING_RETRY;
    }
  }
#if 0
  struct ble_gap_conn_desc desc;
  int rc;

  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      LOG(LL_INFO, ("CONNECT %d %u", event->connect.status, event->connect.conn_handle));
      if (event->connect.status == 0) {
        rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
        assert(rc == 0);
        //bleprph_print_conn_desc(&desc);
      }
      MODLOG_DFLT(INFO, "\n");

      if (event->connect.status != 0) {
        /* Connection failed; resume advertising. */
        bleprph_advertise();
      }
      return 0;

    case BLE_GAP_EVENT_DISCONNECT:
      MODLOG_DFLT(INFO, "disconnect; reason=%d ", event->disconnect.reason);
      bleprph_print_conn_desc(&event->disconnect.conn);
      MODLOG_DFLT(INFO, "\n");

      /* Connection terminated; resume advertising. */
      bleprph_advertise();
      return 0;

    case BLE_GAP_EVENT_CONN_UPDATE:
      /* The central has updated the connection parameters. */
      MODLOG_DFLT(INFO, "connection updated; status=%d ",
                  event->conn_update.status);
      rc = ble_gap_conn_find(event->conn_update.conn_handle, &desc);
      assert(rc == 0);
      bleprph_print_conn_desc(&desc);
      MODLOG_DFLT(INFO, "\n");
      return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
      MODLOG_DFLT(INFO, "advertise complete; reason=%d",
                  event->adv_complete.reason);
      bleprph_advertise();
      return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
      /* Encryption has been enabled or disabled for this connection. */
      MODLOG_DFLT(INFO, "encryption change event; status=%d ",
                  event->enc_change.status);
      rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
      assert(rc == 0);
      bleprph_print_conn_desc(&desc);
      MODLOG_DFLT(INFO, "\n");
      return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
      MODLOG_DFLT(INFO,
                  "subscribe event; conn_handle=%d attr_handle=%d "
                  "reason=%d prevn=%d curn=%d previ=%d curi=%d\n",
                  event->subscribe.conn_handle, event->subscribe.attr_handle,
                  event->subscribe.reason, event->subscribe.prev_notify,
                  event->subscribe.cur_notify, event->subscribe.prev_indicate,
                  event->subscribe.cur_indicate);
      return 0;

    case BLE_GAP_EVENT_MTU:
      MODLOG_DFLT(INFO, "mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                  event->mtu.conn_handle, event->mtu.channel_id,
                  event->mtu.value);
      return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
      /* We already have a bond with the peer, but it is attempting to
       * establish a new secure link.  This app sacrifices security for
       * convenience: just throw away the old bond and accept the new link.
       */

      /* Delete the old bond. */
      rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
      assert(rc == 0);
      ble_store_util_delete_peer(&desc.peer_id_addr);

      /* Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
       * continue with the pairing operation.
       */
      return BLE_GAP_REPEAT_PAIRING_RETRY;

    case BLE_GAP_EVENT_PASSKEY_ACTION:
      ESP_LOGI(tag, "PASSKEY_ACTION_EVENT started \n");
      struct ble_sm_io pkey = {0};
      int key = 0;

      if (event->passkey.params.action == BLE_SM_IOACT_DISP) {
        pkey.action = event->passkey.params.action;
        pkey.passkey = 123456;  // This is the passkey to be entered on peer
        ESP_LOGI(tag, "Enter passkey %d on the peer side", pkey.passkey);
        rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
        ESP_LOGI(tag, "ble_sm_inject_io result: %d\n", rc);
      } else if (event->passkey.params.action == BLE_SM_IOACT_NUMCMP) {
        ESP_LOGI(tag, "Passkey on device's display: %d",
                 event->passkey.params.numcmp);
        ESP_LOGI(tag,
                 "Accept or reject the passkey through console in this format "
                 "-> key Y or key N");
        pkey.action = event->passkey.params.action;
        if (scli_receive_key(&key)) {
          pkey.numcmp_accept = key;
        } else {
          pkey.numcmp_accept = 0;
          ESP_LOGE(tag, "Timeout! Rejecting the key");
        }
        rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
        ESP_LOGI(tag, "ble_sm_inject_io result: %d\n", rc);
      } else if (event->passkey.params.action == BLE_SM_IOACT_OOB) {
        static uint8_t tem_oob[16] = {0};
        pkey.action = event->passkey.params.action;
        for (int i = 0; i < 16; i++) {
          pkey.oob[i] = tem_oob[i];
        }
        rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
        ESP_LOGI(tag, "ble_sm_inject_io result: %d\n", rc);
      } else if (event->passkey.params.action == BLE_SM_IOACT_INPUT) {
        ESP_LOGI(
            tag,
            "Enter the passkey through console in this format-> key 123456");
        pkey.action = event->passkey.params.action;
        if (scli_receive_key(&key)) {
          pkey.passkey = key;
        } else {
          pkey.passkey = 0;
          ESP_LOGE(tag, "Timeout! Passing 0 as the key");
        }
        rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
        ESP_LOGI(tag, "ble_sm_inject_io result: %d\n", rc);
      }
      return 0;
  }
#endif
  return 0;
}

bool mgos_bt_gap_set_scan_rsp_data(struct mg_str scan_rsp_data) {
  return (ble_gap_adv_rsp_set_data((const uint8_t *) scan_rsp_data.p,
                                   scan_rsp_data.len) == 0);
}

static bool start_advertising(void) {
  int rc;

  if (s_advertising) return true;
  if (!s_adv_enable) return false;
  const char *dev_name = mgos_sys_config_get_bt_dev_name();
  if (dev_name == NULL) dev_name = mgos_sys_config_get_device_id();
  if (dev_name == NULL) {
    LOG(LL_ERROR, ("bt.dev_name or device.id must be set"));
    return false;
  }
  if (ble_svc_gap_device_name_set(dev_name) != 0) {
    return false;
  }

  struct ble_hs_adv_fields fields = {
      .flags = 0,

      .name = (uint8_t *) dev_name,
      .name_len = strlen(dev_name),
      .name_is_complete = true,

      .tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO,
      .tx_pwr_lvl_is_present = true,
  };
  if ((rc = ble_gap_adv_set_fields(&fields)) != 0) {
    LOG(LL_ERROR, ("ble_gap_adv_set_fields: %d", rc));
    return false;
  }

  struct mg_str scan_rsp_data_hex =
      mg_mk_str(mgos_sys_config_get_bt_scan_rsp_data_hex());
  if (scan_rsp_data_hex.len > 0) {
    struct mg_str scan_rsp_data = MG_NULL_STR;
    json_scanf(scan_rsp_data_hex.p, scan_rsp_data_hex.len, "%H",
               &scan_rsp_data.len, &scan_rsp_data.p);
    if (scan_rsp_data.len > 0) {
      if (scan_rsp_data.len <= MGOS_BT_GAP_MAX_SCAN_RSP_DATA_LEN) {
        mgos_bt_gap_set_scan_rsp_data(scan_rsp_data);
        LOG(LL_INFO, ("Scan rsp len %d", scan_rsp_data.len));
      } else {
        LOG(LL_ERROR, ("Scan response data too long (%d), max is %d",
                       scan_rsp_data.len, MGOS_BT_GAP_MAX_SCAN_RSP_DATA_LEN));
      }
      free((void *) scan_rsp_data.p);
    }
  }

  struct ble_gap_adv_params adv_params = {
      .conn_mode = BLE_GAP_CONN_MODE_UND,
      .disc_mode = BLE_GAP_DISC_MODE_GEN,
      .itvl_min = BLE_GAP_ADV_FAST_INTERVAL2_MIN,
      .itvl_max = BLE_GAP_ADV_FAST_INTERVAL2_MAX,
      .channel_map = BLE_GAP_ADV_DFLT_CHANNEL_MAP,
  };
  if ((rc = ble_hs_id_infer_auto(0, &own_addr_type)) != 0) {
    LOG(LL_ERROR, ("ble_hs_id_infer_auto: %d", rc));
    return false;
  }

  if ((rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &adv_params,
                              esp32_bt_gap_event, NULL)) != 0) {
    LOG(LL_ERROR, ("ble_hs_id_infer_auto: %d", rc));
    return false;
  }

  struct mgos_bt_addr addr;
  if (mgos_bt_get_device_address(&addr)) {
    char addr_str[MGOS_BT_ADDR_STR_LEN] = {0};
    LOG(LL_INFO,
        ("Advertising name %s, addr %s", dev_name,
         mgos_bt_addr_to_str(&addr, MGOS_BT_ADDR_STRINGIFY_TYPE, addr_str)));
  }
  return true;
}

static bool stop_advertising(void) {
  if (!s_advertising) return true;
  return (ble_gap_adv_stop() == 0);
}

bool mgos_bt_gap_get_adv_enable(void) {
  return s_adv_enable;
}

bool mgos_bt_gap_set_adv_enable(bool adv_enable) {
  s_adv_enable = adv_enable;
  return (s_adv_enable ? start_advertising() : stop_advertising());
}

bool esp32_bt_gap_init(void) {
  return true;
}
