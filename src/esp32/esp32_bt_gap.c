/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#include "esp32_bt.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "bta_api.h"
#include "esp_bt.h"
#include "esp_bt_defs.h"
#include "esp_gap_ble_api.h"

#include "frozen/frozen.h"

#include "mgos_system.h"
#include "mgos_sys_config.h"

#include "esp32_bt_internal.h"
#include "esp32_bt_gatts.h"

struct scan_cb_info {
  esp_bd_addr_t target_addr;
  struct mg_str target_name;
  mgos_bt_ble_scan_cb_t cb;
  void *cb_arg;
  SLIST_ENTRY(scan_cb_info) next;
};

struct scan_ctx {
  int duration;
  int num_res;
  struct mgos_bt_ble_scan_result *res;
  SLIST_HEAD(cbs, scan_cb_info) cbs;
};

struct scan_ctx *s_scan_ctx = NULL;

static bool s_adv_enable = false, s_advertising = false;
/* TODO(rojer): Make configurable */
static esp_ble_adv_data_t s_adv_data = {
    .set_scan_rsp = false,
    .include_name = true,
    .include_txpower = true,
    .min_interval = 0x100, /* 0x100 * 0.625 = 100 ms */
    .max_interval = 0x200, /* 0x200 * 0.625 = 200 ms */
    .appearance = 0x00,
    .manufacturer_len = 0,
    .p_manufacturer_data = NULL,
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = 0,
    .p_service_uuid = NULL,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
static esp_ble_adv_params_t s_adv_params = {
    .adv_int_min = 0x50,  /* 0x100 * 0.625 = 100 ms */
    .adv_int_max = 0x100, /* 0x200 * 0.625 = 200 ms */
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static bool s_pairing_enable = false;

static bool start_advertising(void) {
  if (s_advertising) return true;
  if (!s_adv_enable || is_scanning()) return false;
  const char *dev_name = mgos_sys_config_get_bt_dev_name();
  if (dev_name == NULL) dev_name = mgos_sys_config_get_device_id();
  if (dev_name == NULL) {
    LOG(LL_ERROR, ("bt.dev_name or device.id must be set"));
    return false;
  }
  LOG(LL_INFO, ("BT device name %s", dev_name));
  if (esp_ble_gap_set_device_name(dev_name) != ESP_OK) {
    return false;
  }
  if (esp_ble_gap_config_adv_data(&s_adv_data)) {
    LOG(LL_ERROR, ("Failed to set adv data"));
    return false;
  }
  return true;
}

static bool stop_advertising(void) {
  if (!s_advertising) return true;
  return (esp_ble_gap_stop_advertising() == ESP_OK);
}

bool is_scanning(void) {
  return (s_scan_ctx != NULL);
}

static void scan_ctx_done(struct scan_ctx *sctx, int status);
static void scan_done(int status);

static void esp32_bt_gap_ev(esp_gap_ble_cb_event_t ev,
                            esp_ble_gap_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT: {
      const struct ble_adv_data_cmpl_evt_param *p = &ep->adv_data_cmpl;
      LOG(LL_DEBUG, ("ADV_DATA_SET_COMPLETE st %d", p->status));
      if (s_adv_enable && !is_scanning()) {
        esp_ble_gap_start_advertising(&s_adv_params);
      }
      break;
    }
    case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT: {
      const struct ble_scan_rsp_data_cmpl_evt_param *p =
          &ep->scan_rsp_data_cmpl;
      LOG(LL_DEBUG, ("SCAN_RSP_DATA_SET_COMPLETE st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT: {
      const struct ble_scan_param_cmpl_evt_param *p = &ep->scan_param_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SCAN_PARAM_SET_COMPLETE st %d", p->status));
      if (p->status != ESP_BT_STATUS_SUCCESS) {
        scan_done(-2);
        break;
      }
      /*
       * Scanning and advertising is incompatible.
       * If we are advertising, suspend to perform a scan.
       */
      if (s_advertising) {
        if (!stop_advertising()) {
          scan_done(-3);
        }
      } else if (is_scanning()) {
        if (esp_ble_gap_start_scanning(s_scan_ctx->duration) != ESP_OK) {
          scan_done(-4);
        }
      }
      break;
    }
    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
      struct ble_scan_result_evt_param *p = &ep->scan_rst;
      switch (p->search_evt) {
        case ESP_GAP_SEARCH_INQ_RES_EVT: {
          uint8_t name_len = 0;
          uint8_t *name = esp_ble_resolve_adv_data(
              p->ble_adv, ESP_BLE_AD_TYPE_NAME_CMPL, &name_len);
          LOG(LL_DEBUG,
              ("SCAN_RESULT addr %s name %.*s type %d RSSI %d adl %d srl %d",
               mgos_bt_addr_to_str(p->bda, buf), (int) name_len,
               (name ? (const char *) name : ""), p->dev_type, p->rssi,
               p->adv_data_len, p->scan_rsp_len));
          struct mgos_bt_ble_scan_result *r = NULL;
          struct scan_ctx *sctx = s_scan_ctx;
          if (sctx == NULL) break;
          for (int i = 0; i < sctx->num_res; i++) {
            if (mgos_bt_addr_cmp(sctx->res[i].addr, p->bda) == 0) {
              r = &sctx->res[i];
              free((void *) r->adv_data.p);
              break;
            }
          }
          if (r == NULL) {
            sctx->res = realloc(sctx->res, (sctx->num_res + 1) * sizeof(*r));
            r = &sctx->res[sctx->num_res++];
          }
          memset(r, 0, sizeof(*r));
          r->adv_data = mg_strdup(mg_mk_str_n(
              (const char *) p->ble_adv, p->adv_data_len + p->scan_rsp_len));
          r->adv_data.len = p->adv_data_len;
          if (p->scan_rsp_len > 0) {
            r->scan_rsp.p = r->adv_data.p + p->adv_data_len;
            r->scan_rsp.len = p->scan_rsp_len;
          }
          memcpy(&r->addr, &p->bda, sizeof(r->addr));
          memcpy(r->name, name, name_len);
          r->rssi = p->rssi;
          /* See if there are any scans waiting for this specific device */
          struct scan_cb_info *cbi, *cbit;
          SLIST_FOREACH_SAFE(cbi, &sctx->cbs, next, cbit) {
            if (mgos_bt_addr_cmp(r->addr, cbi->target_addr) == 0 ||
                (name_len > 0 &&
                 mg_strcmp(mg_mk_str_n(r->name, name_len), cbi->target_name) ==
                     0)) {
              /* Create a copy of this one result and fire the callback. */
              struct scan_ctx *tsctx =
                  (struct scan_ctx *) calloc(1, sizeof(*tsctx));
              tsctx->num_res = 1;
              tsctx->res = calloc(1, sizeof(*r));
              memcpy(tsctx->res, r, sizeof(*r));
              /* Avoid double-free (name -> addr resolver doesn't need adv data
               * anyway). */
              tsctx->res->adv_data.p = NULL;
              tsctx->res->adv_data.len = 0;
              SLIST_REMOVE(&sctx->cbs, cbi, scan_cb_info, next);
              SLIST_INSERT_HEAD(&tsctx->cbs, cbi, next);
              scan_ctx_done(tsctx, 0);
            }
          }
          if (SLIST_EMPTY(&sctx->cbs)) esp_ble_gap_stop_scanning();
          break;
        }
        case ESP_GAP_SEARCH_INQ_CMPL_EVT: {
          LOG(LL_DEBUG,
              ("SCAN_COMPLETE %d", (s_scan_ctx ? s_scan_ctx->num_res : -1)));
          scan_done(0);
          break;
        }
        default: { LOG(LL_DEBUG, ("SCAN_RESULT %d", p->search_evt)); }
      }
      break;
    }
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT: {
      const struct ble_adv_data_raw_cmpl_evt_param *p = &ep->adv_data_raw_cmpl;
      LOG(LL_DEBUG, ("ADV_DATA_RAW_SET_COMPLETE st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT: {
      const struct ble_scan_rsp_data_raw_cmpl_evt_param *p =
          &ep->scan_rsp_data_raw_cmpl;
      LOG(LL_DEBUG, ("SCAN_RSP_DATA_RAW_SET_COMPLETE st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT: {
      const struct ble_adv_start_cmpl_evt_param *p = &ep->adv_start_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("ADV_START_COMPLETE st %d", p->status));
      if (p->status == ESP_BT_STATUS_SUCCESS) {
        s_advertising = true;
        LOG(LL_INFO, ("BLE advertising started"));
      }
      break;
    }
    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT: {
      const struct ble_scan_start_cmpl_evt_param *p = &ep->scan_start_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SCAN_START_COMPLETE st %d", p->status));
      if (p->status != ESP_BT_STATUS_SUCCESS) {
        scan_done(-3);
      }
      LOG(LL_INFO, ("BLE scan started"));
      break;
    }
    case ESP_GAP_BLE_AUTH_CMPL_EVT: {
      const esp_ble_auth_cmpl_t *p = &ep->ble_security.auth_cmpl;
      enum cs_log_level ll = (p->success ? LL_INFO : LL_ERROR);
      LOG(ll, ("AUTH_CMPL peer %s at %d dt %d success %d (fr %d) kp %d kt %d",
               mgos_bt_addr_to_str(p->bd_addr, buf), p->addr_type, p->dev_type,
               p->success, p->fail_reason, p->key_present, p->key_type));
      if (p->success) esp32_bt_gatts_auth_cmpl(p->bd_addr);
      break;
    }
    case ESP_GAP_BLE_KEY_EVT: {
      const esp_ble_key_t *p = &ep->ble_security.ble_key;
      LOG(LL_DEBUG, ("KEY peer %s kt %d", mgos_bt_addr_to_str(p->bd_addr, buf),
                     p->key_type));
      break;
    }
    case ESP_GAP_BLE_SEC_REQ_EVT: {
      esp_ble_sec_req_t *p = &ep->ble_security.ble_req;
      LOG(LL_DEBUG, ("SEC_REQ peer %s", mgos_bt_addr_to_str(p->bd_addr, buf)));
      esp_ble_gap_security_rsp(p->bd_addr, true /* accept */);
      break;
    }
    case ESP_GAP_BLE_PASSKEY_NOTIF_EVT: {
      esp_ble_sec_key_notif_t *p = &ep->ble_security.key_notif;
      LOG(LL_DEBUG, ("PASSKEY_NOTIF peer %s pk %u",
                     mgos_bt_addr_to_str(p->bd_addr, buf), p->passkey));
      /*
       * TODO(rojer): Provide a callback interface for user to display the code.
       * For now, hope people read the logs. Yeah.
       */
      LOG(LL_ERROR, ("The passkey to pair with %s is %u",
                     mgos_bt_addr_to_str(p->bd_addr, buf), p->passkey));
      break;
    }
    case ESP_GAP_BLE_PASSKEY_REQ_EVT: {
      LOG(LL_DEBUG, ("PASSKEY_REQ"));
      break;
    }
    case ESP_GAP_BLE_OOB_REQ_EVT: {
      LOG(LL_DEBUG, ("OOB_REQ"));
      break;
    }
    case ESP_GAP_BLE_LOCAL_IR_EVT: {
      LOG(LL_DEBUG, ("LOCAL_IR"));
      break;
    }
    case ESP_GAP_BLE_LOCAL_ER_EVT: {
      LOG(LL_DEBUG, ("LOCAL_ER"));
      break;
    }
    case ESP_GAP_BLE_NC_REQ_EVT: {
      LOG(LL_DEBUG, ("NC_REQ"));
      break;
    }
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT: {
      const struct ble_adv_stop_cmpl_evt_param *p = &ep->adv_stop_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("ADV_STOP_COMPLETE st %d", p->status));
      if (p->status == ESP_BT_STATUS_SUCCESS) {
        s_advertising = false;
        LOG(LL_INFO, ("BLE advertising stopped"));
      }
      if (is_scanning()) {
        if (esp_ble_gap_start_scanning(s_scan_ctx->duration) != ESP_OK) {
          scan_done(-5);
        }
      }
      break;
    }
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT: {
      const struct ble_scan_stop_cmpl_evt_param *p = &ep->scan_stop_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SCAN_STOP_COMPLETE st %d", p->status));
      scan_done(0);
      break;
    }
    case ESP_GAP_BLE_SET_STATIC_RAND_ADDR_EVT: {
      const struct ble_set_rand_cmpl_evt_param *p = &ep->set_rand_addr_cmpl;
      LOG(LL_DEBUG, ("SET_STATIC_RAND_ADDR st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT: {
      const struct ble_update_conn_params_evt_param *p =
          &ep->update_conn_params;
      LOG(LL_DEBUG, ("UPDATE_CONN_PARAMS st %d addr %s int %u-%u lat %u "
                     "conn_int %u tout %u",
                     p->status, mgos_bt_addr_to_str(p->bda, buf), p->min_int,
                     p->max_int, p->latency, p->conn_int, p->timeout));
      break;
    }
    case ESP_GAP_BLE_SET_PKT_LENGTH_COMPLETE_EVT: {
      const struct ble_pkt_data_length_cmpl_evt_param *p =
          &ep->pkt_data_lenth_cmpl;
      LOG(LL_DEBUG, ("SET_PKT_LENGTH_COMPLETE st %d rx_len %u tx_len %u",
                     p->status, p->params.rx_len, p->params.tx_len));
      break;
    }
    case ESP_GAP_BLE_SET_LOCAL_PRIVACY_COMPLETE_EVT: {
      const struct ble_local_privacy_cmpl_evt_param *p =
          &ep->local_privacy_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SET_LOCAL_PRIVACY_COMPLETE st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_REMOVE_BOND_DEV_COMPLETE_EVT: {
      const struct ble_remove_bond_dev_cmpl_evt_param *p =
          &ep->remove_bond_dev_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REMOVE_BOND_DEV_COMPLETE st %d bda %s", p->status,
               mgos_bt_addr_to_str(p->bd_addr, buf)));
      break;
    }
    case ESP_GAP_BLE_CLEAR_BOND_DEV_COMPLETE_EVT: {
      const struct ble_clear_bond_dev_cmpl_evt_param *p =
          &ep->clear_bond_dev_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CLEAR_BOND_DEV_COMPLETE st %d", p->status));
      break;
    }
    case ESP_GAP_BLE_GET_BOND_DEV_COMPLETE_EVT: {
      const struct ble_get_bond_dev_cmpl_evt_param *p = &ep->get_bond_dev_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      if (p->status != ESP_BT_STATUS_SUCCESS) {
        LOG(ll, ("GET_BOND_DEV_COMPLETE st %d", p->status));
      } else {
        LOG(ll,
            ("GET_BOND_DEV_COMPLETE st %d dev_num %d peer_addr %s", p->status,
             p->dev_num, mgos_bt_addr_to_str(p->bond_dev->bd_addr, buf)));
      }
      break;
    }
    case ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT: {
      const struct ble_read_rssi_cmpl_evt_param *p = &ep->read_rssi_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("READ_RSSI_COMPLETE st %d rssi %d ra %s", p->status, p->rssi,
               mgos_bt_addr_to_str(p->remote_addr, buf)));
      break;
    }
    case ESP_GAP_BLE_ADD_WHITELIST_COMPLETE_EVT: {
      const struct ble_add_whitelist_cmpl_evt_param *p =
          &ep->add_whitelist_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("ADD_WHITELIST_COMPLETE st %d op %d", p->status, p->wl_opration));
      break;
    }
    case ESP_GAP_BLE_EVT_MAX: {
      break;
    }
  }
}

static void scan_done_mgos_cb(void *arg) {
  struct scan_ctx *sctx = (struct scan_ctx *) arg;
  struct scan_cb_info *cbi, *cbit;
  SLIST_FOREACH_SAFE(cbi, &sctx->cbs, next, cbit) {
    if (cbi->cb == NULL) continue;
    int num_res = sctx->num_res;
    if (num_res >= 1 &&
        ((!mgos_bt_addr_is_null(cbi->target_addr) &&
          mgos_bt_addr_cmp(sctx->res->addr, cbi->target_addr) != 0) ||
         (cbi->target_name.len > 0 &&
          mg_strcmp(mg_mk_str(sctx->res->name), cbi->target_name) != 0))) {
      num_res = 0;
    }
    cbi->cb(num_res, (num_res > 0 ? sctx->res : NULL), cbi->cb_arg);
    free((void *) cbi->target_name.p);
    free(cbi);
  }
  for (int i = 0; i < sctx->num_res; i++) {
    free((void *) sctx->res[i].adv_data.p);
  }
  free(sctx->res);
  free(sctx);
}

static void scan_ctx_done(struct scan_ctx *sctx, int status) {
  if (status < 0) sctx->num_res = status;
  LOG(LL_INFO, ("BLE scan done, %d", sctx->num_res));
  if (s_adv_enable) { /* Resume advertising */
    start_advertising();
  }
  mgos_invoke_cb(scan_done_mgos_cb, sctx, false /* from_isr */);
}

static void scan_done(int status) {
  struct scan_ctx *sctx = s_scan_ctx;
  if (sctx == NULL) return;
  s_scan_ctx = NULL;
  scan_ctx_done(sctx, status);
}

void mgos_bt_ble_scan(const struct mgos_bt_ble_scan_opts *opts,
                      mgos_bt_ble_scan_cb_t cb, void *cb_arg) {
  struct scan_cb_info *cbi = (struct scan_cb_info *) calloc(1, sizeof(*cbi));
  if (cbi == NULL) return;
  cbi->cb = cb;
  cbi->cb_arg = cb_arg;
  memcpy(cbi->target_addr, opts->addr, sizeof(cbi->target_addr));
  cbi->target_name = mg_strdup(opts->name);
  int scan_interval_ms =
      (opts->interval_ms > 0 ? opts->interval_ms
                             : MGOS_BT_BLE_DEFAULT_SCAN_INTERVAL_MS);
  int scan_window_ms =
      (opts->window_ms > 0 ? opts->window_ms
                           : MGOS_BT_BLE_DEFAULT_SCAN_WINDOW_MS);
  esp_ble_scan_params_t params = {
      .scan_type =
          (opts->active ? BLE_SCAN_TYPE_ACTIVE : BLE_SCAN_TYPE_PASSIVE),
      .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
      .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
      /* Time units: 0.625 ms */
      .scan_interval = scan_interval_ms / 0.625,
      .scan_window = scan_window_ms / 0.625,
  };
  if (s_scan_ctx == NULL) {
    struct scan_ctx *sctx = (struct scan_ctx *) calloc(1, sizeof(*sctx));
    SLIST_INSERT_HEAD(&sctx->cbs, cbi, next);
    sctx->duration =
        (opts->duration_ms > 0 ? opts->duration_ms
                               : MGOS_BT_BLE_DEFAULT_SCAN_DURATION_MS) /
        1000,
    s_scan_ctx = sctx;
    if (esp_ble_gap_set_scan_params(&params) == ESP_OK) {
      LOG(LL_DEBUG, ("Starting scan (%s, %ds, %d/%d)",
                     (opts->active ? "active" : "passive"), sctx->duration,
                     scan_window_ms, scan_interval_ms));
    } else {
      scan_done(-1);
    }
  } else {
    LOG(LL_DEBUG, ("Scan already in progress"));
    SLIST_INSERT_HEAD(&s_scan_ctx->cbs, cbi, next);
  }
}

void mgos_bt_ble_set_scan_rsp_data(const struct mg_str scan_rsp_data) {
  esp_ble_gap_config_scan_rsp_data_raw((uint8_t *) scan_rsp_data.p,
                                       scan_rsp_data.len);
}

bool mgos_bt_gap_get_adv_enable(void) {
  return s_adv_enable;
}

bool mgos_bt_gap_set_adv_enable(bool adv_enable) {
  s_adv_enable = adv_enable;
  return (s_adv_enable ? start_advertising() : stop_advertising());
}

void esp32_bt_set_is_advertising(bool is_advertising) {
  s_advertising = is_advertising;
}

bool mgos_bt_gap_get_pairing_enable(void) {
  return s_pairing_enable;
}

bool mgos_bt_gap_set_pairing_enable(bool pairing_enable) {
  esp_ble_auth_req_t auth_req =
      (pairing_enable ? ESP_LE_AUTH_BOND : ESP_LE_AUTH_NO_BOND);
  if (esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth_req,
                                     sizeof(auth_req)) == ESP_OK) {
    s_pairing_enable = pairing_enable;
    return true;
  } else {
    return false;
  }
}

void mgos_bt_ble_remove_paired_device(const esp_bd_addr_t addr) {
  /* Workaround for https://github.com/espressif/esp-idf/issues/1365 */
  if (mgos_bt_gatts_get_num_connections() > 0) {
    esp_ble_gap_disconnect((uint8_t *) addr);
    /* After disconnecting, some time is required before
     * esp_ble_remove_bond_device can succeed. */
    mgos_msleep(200);
  }

  esp_ble_remove_bond_device((uint8_t *) addr);
}

void mgos_bt_ble_remove_all_paired_devices(void) {
  int num = esp_ble_get_bond_device_num();
  esp_ble_bond_dev_t *list = (esp_ble_bond_dev_t *) calloc(num, sizeof(*list));
  if (list != NULL && esp_ble_get_bond_device_list(&num, list) == ESP_OK) {
    for (int i = 0; i < num; i++) {
      mgos_bt_ble_remove_paired_device(list[i].bd_addr);
    }
  }
  free(list);
}

bool esp32_bt_gap_init(void) {
  if (esp_ble_gap_register_callback(esp32_bt_gap_ev) != ESP_OK) {
    return false;
  }

  struct mg_str scan_rsp_data_hex =
      mg_mk_str(mgos_sys_config_get_bt_scan_rsp_data_hex());
  if (scan_rsp_data_hex.len > 0) {
    struct mg_str scan_rsp_data = MG_NULL_STR;
    json_scanf(scan_rsp_data_hex.p, scan_rsp_data_hex.len, "%H",
               &scan_rsp_data.len, &scan_rsp_data.p);
    if (scan_rsp_data.len > 0) {
      if (scan_rsp_data.len <= MGOS_BT_BLE_MAX_SCAN_RSP_DATA_LEN) {
        mgos_bt_ble_set_scan_rsp_data(scan_rsp_data);
        LOG(LL_INFO, ("Scan rsp len %d", scan_rsp_data.len));
      } else {
        LOG(LL_ERROR, ("Scan response data too long (%d), max is %d",
                       scan_rsp_data.len, MGOS_BT_BLE_MAX_SCAN_RSP_DATA_LEN));
      }
      free((void *) scan_rsp_data.p);
    }
  }

  mgos_bt_gap_set_pairing_enable(mgos_sys_config_get_bt_allow_pairing());

  esp_ble_io_cap_t io_cap = ESP_IO_CAP_NONE;
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &io_cap,
                                 sizeof(uint8_t));
  uint8_t key_size = 16;
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size,
                                 sizeof(key_size));

  return mgos_bt_gap_set_adv_enable(mgos_sys_config_get_bt_adv_enable());
}
