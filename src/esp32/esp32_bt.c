/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#include "esp32_bt.h"
#include "esp32_bt_internal.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "bt.h"
#include "bta_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"

#include "common/mg_str.h"

#include "mgos_hal.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"

static bool s_advertising = false;

static esp_ble_adv_params_t mos_adv_params = {
    .adv_int_min = 0x50,  /* 0x100 * 0.625 = 100 ms */
    .adv_int_max = 0x100, /* 0x200 * 0.625 = 200 ms */
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

#define MGOS_BT_BLE_SCAN_DURATION (5 /* seconds */)
static esp_ble_scan_params_t ble_scan_params = {
    .scan_type = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval = 0x100, /* 0x100 * 0.625 = 100 ms */
    .scan_window = 0x80,    /* 0x50 * 0.625 = 50 ms */
};

struct scan_cb_info {
  esp_bd_addr_t target_addr;
  struct mg_str target_name;
  mgos_bt_ble_scan_cb_t cb;
  void *cb_arg;
  SLIST_ENTRY(scan_cb_info) next;
};

struct scan_ctx {
  int num_res;
  struct mgos_bt_ble_scan_result *res;
  SLIST_HEAD(cbs, scan_cb_info) cbs;
};

struct scan_ctx *s_scan_ctx = NULL;

const char *mgos_bt_addr_to_str(const esp_bd_addr_t addr, char *out) {
  sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2],
          addr[3], addr[4], addr[5]);
  return out;
}

bool mgos_bt_addr_from_str(const struct mg_str addr_str, esp_bd_addr_t addr) {
  unsigned int a[6];
  struct mg_str addr_str_nul = mg_strdup_nul(addr_str);
  bool result = (sscanf(addr_str_nul.p, "%02x:%02x:%02x:%02x:%02x:%02x", &a[0],
                        &a[1], &a[2], &a[3], &a[4], &a[5]) == 6);
  if (result) {
    for (int i = 0; i < 6; i++) {
      addr[i] = a[i];
    }
  }
  free((void *) addr_str_nul.p);
  return result;
}

int mgos_bt_addr_cmp(const esp_bd_addr_t a, const esp_bd_addr_t b) {
  return memcmp(a, b, ESP_BD_ADDR_LEN);
}

bool mgos_bt_addr_is_null(const esp_bd_addr_t a) {
  const esp_bd_addr_t null_addr = {0};
  return (mgos_bt_addr_cmp(a, null_addr) == 0);
}

const char *bt_uuid128_to_str(const uint8_t *u, char *out) {
  sprintf(out,
          "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
          "%02x%02x%02x%02x%02x%02x",
          u[15], u[14], u[13], u[12], u[11], u[10], u[9], u[8], u[7], u[6],
          u[5], u[4], u[3], u[2], u[1], u[0]);
  return out;
}

const char *mgos_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out) {
  switch (uuid->len) {
    case ESP_UUID_LEN_16: {
      sprintf(out, "%04x", uuid->uuid.uuid16);
      break;
    }
    case ESP_UUID_LEN_32: {
      sprintf(out, "%08x", uuid->uuid.uuid32);
      break;
    }
    case ESP_UUID_LEN_128: {
      bt_uuid128_to_str(uuid->uuid.uuid128, out);
      break;
    }
    default: { sprintf(out, "?(%u)", uuid->len); }
  }
  return out;
}

bool mgos_bt_uuid_from_str(const struct mg_str uuid_str, esp_bt_uuid_t *uuid) {
  bool result = false;
  struct mg_str uuid_str_nul = mg_strdup_nul(uuid_str);
  if (uuid_str.len == 36) {
    unsigned int u[16];
    if (sscanf(uuid_str_nul.p,
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
               "%02x%02x%02x%02x%02x%02x",
               &u[15], &u[14], &u[13], &u[12], &u[11], &u[10], &u[9], &u[8],
               &u[7], &u[6], &u[5], &u[4], &u[3], &u[2], &u[1], &u[0]) == 16) {
      result = true;
      uuid->len = ESP_UUID_LEN_128;
      for (int i = 0; i < 16; i++) {
        uuid->uuid.uuid128[i] = u[i];
      }
    }
  } else if (uuid_str.len <= 8) {
    unsigned int u;
    if (sscanf(uuid_str_nul.p, "%08x", &u) == 1) {
      result = true;
      if (u & 0xffff0000) {
        uuid->len = ESP_UUID_LEN_32;
        uuid->uuid.uuid32 = u;
      } else {
        uuid->len = ESP_UUID_LEN_16;
        uuid->uuid.uuid16 = u;
      }
    }
  }
  free((void *) uuid_str_nul.p);
  return result;
}

int mgos_bt_uuid_cmp(const esp_bt_uuid_t *a, const esp_bt_uuid_t *b) {
  int result = 0;
  if (a->len == ESP_UUID_LEN_128 || b->len == ESP_UUID_LEN_128) {
    /* 128-bit UUID is always > 16 or 32-bit */
    if (a->len != ESP_UUID_LEN_128 && b->len == ESP_UUID_LEN_128) {
      result = -1;
    } else if (a->len == ESP_UUID_LEN_128 && b->len != ESP_UUID_LEN_128) {
      result = 1;
    } else {
      for (int i = 15; i >= 0; i--) {
        uint8_t va = a->uuid.uuid128[i];
        uint8_t vb = b->uuid.uuid128[i];
        if (va != vb) {
          result = (va > vb ? 1 : -1);
          break;
        }
      }
    }
  } else {
    uint32_t va, vb;
    va = (a->len == ESP_UUID_LEN_16 ? a->uuid.uuid16 : a->uuid.uuid32);
    vb = (b->len == ESP_UUID_LEN_16 ? b->uuid.uuid16 : b->uuid.uuid32);
    if (va < vb) {
      result = -1;
    } else if (va > vb) {
      result = 1;
    }
  }
  return result;
}

enum cs_log_level ll_from_status(esp_bt_status_t status) {
  return (status == ESP_BT_STATUS_SUCCESS ? LL_DEBUG : LL_ERROR);
}

bool is_advertising(void) {
  return s_advertising;
}

bool start_advertising(void) {
  return (esp_ble_gap_start_advertising(&mos_adv_params) == ESP_OK);
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
      if (mgos_sys_config_get_bt_adv_enable() && !is_scanning()) {
        start_advertising();
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
        if (esp_ble_gap_stop_advertising() != ESP_OK) {
          scan_done(-3);
        }
      } else {
        if (esp_ble_gap_start_scanning(MGOS_BT_BLE_SCAN_DURATION) != ESP_OK) {
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
              ("SCAN_RESULT addr %s name %.*s type %d RSSI %d",
               mgos_bt_addr_to_str(p->bda, buf), (int) name_len,
               (name ? (const char *) name : ""), p->dev_type, p->rssi));
          struct mgos_bt_ble_scan_result *r = NULL;
          struct scan_ctx *sctx = s_scan_ctx;
          if (sctx == NULL) break;
          for (int i = 0; i < sctx->num_res; i++) {
            if (mgos_bt_addr_cmp(sctx->res[i].addr, p->bda) == 0) {
              r = &sctx->res[i];
              break;
            }
          }
          if (r == NULL) {
            sctx->res = realloc(sctx->res, (sctx->num_res + 1) * sizeof(*r));
            r = &sctx->res[sctx->num_res++];
          }
          memset(r, 0, sizeof(*r));
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
      LOG(LL_DEBUG, ("AUTH_CMPL"));
      break;
    }
    case ESP_GAP_BLE_KEY_EVT: {
      LOG(LL_DEBUG, ("KEY"));
      break;
    }
    case ESP_GAP_BLE_SEC_REQ_EVT: {
      LOG(LL_DEBUG, ("SEC_REQ"));
      break;
    }
    case ESP_GAP_BLE_PASSKEY_NOTIF_EVT: {
      LOG(LL_DEBUG, ("PASSKEY_NOTIF"));
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
        if (esp_ble_gap_start_scanning(MGOS_BT_BLE_SCAN_DURATION) != ESP_OK) {
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
      LOG(LL_DEBUG, ("UPDATE_CONN_PARAMS st %d", p->status));
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
  free(sctx->res);
  free(sctx);
}

static void scan_ctx_done(struct scan_ctx *sctx, int status) {
  if (status < 0) sctx->num_res = status;
  LOG(LL_INFO, ("BLE scan done, %d", sctx->num_res));
  if (mgos_sys_config_get_bt_adv_enable() &&
      !is_advertising()) { /* Resume advertising */
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

static void mgos_bt_ble_scan_device(const esp_bd_addr_t addr,
                                    const struct mg_str name,
                                    mgos_bt_ble_scan_cb_t cb, void *cb_arg) {
  struct scan_cb_info *cbi = (struct scan_cb_info *) calloc(1, sizeof(*cbi));
  if (cbi == NULL) return;
  cbi->cb = cb;
  cbi->cb_arg = cb_arg;
  memcpy(cbi->target_addr, addr, sizeof(cbi->target_addr));
  cbi->target_name = mg_strdup(name);
  if (s_scan_ctx == NULL) {
    struct scan_ctx *sctx = (struct scan_ctx *) calloc(1, sizeof(*sctx));
    SLIST_INSERT_HEAD(&sctx->cbs, cbi, next);
    s_scan_ctx = sctx;
    if (esp_ble_gap_set_scan_params(&ble_scan_params) == ESP_OK) {
      LOG(LL_DEBUG, ("Starting scan"));
    } else {
      scan_done(-1);
    }
  } else {
    LOG(LL_DEBUG, ("Scan already in progress"));
    SLIST_INSERT_HEAD(&s_scan_ctx->cbs, cbi, next);
  }
}

void mgos_bt_ble_scan_device_addr(const esp_bd_addr_t addr,
                                  mgos_bt_ble_scan_cb_t cb, void *cb_arg) {
  struct mg_str name = MG_NULL_STR;
  mgos_bt_ble_scan_device(addr, name, cb, cb_arg);
}

void mgos_bt_ble_scan_device_name(const struct mg_str name,
                                  mgos_bt_ble_scan_cb_t cb, void *cb_arg) {
  esp_bd_addr_t addr;
  memset(&addr, 0, sizeof(addr));
  mgos_bt_ble_scan_device(addr, name, cb, cb_arg);
}

void mgos_bt_ble_scan(mgos_bt_ble_scan_cb_t cb, void *cb_arg) {
  struct mg_str name = MG_NULL_STR;
  esp_bd_addr_t addr;
  memset(&addr, 0, sizeof(addr));
  mgos_bt_ble_scan_device(addr, name, cb, cb_arg);
}

static void mgos_bt_net_ev(enum mgos_net_event ev,
                           const struct mgos_net_event_data *ev_data,
                           void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  LOG(LL_INFO, ("Network is up, disabling Bluetooth"));
  mgos_sys_config_set_bt_enable(false);
  char *msg = NULL;
  if (save_cfg(&mgos_sys_config, &msg)) {
    esp_bt_controller_disable(ESP_BT_MODE_BTDM);
  }
  (void) arg;
}

bool mgos_bt_common_init(void) {
  bool ret = false;
  if (!mgos_sys_config_get_bt_enable()) {
    LOG(LL_INFO, ("Bluetooth is disabled"));
    return true;
  }

  if (!mgos_sys_config_get_bt_keep_enabled()) {
    mgos_net_add_event_handler(mgos_bt_net_ev, NULL);
  }

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_err_t err = esp_bt_controller_init(&bt_cfg);
  if (err) {
    LOG(LL_ERROR, ("BT init failed: %d", err));
    goto out;
  }
  err = esp_bt_controller_enable(ESP_BT_MODE_BTDM);
  if (err) {
    LOG(LL_ERROR, ("BT enable failed: %d", err));
    goto out;
  }
  err = esp_bluedroid_init();
  if (err != ESP_OK) {
    LOG(LL_ERROR, ("bluedroid init failed: %d", err));
    goto out;
  }
  err = esp_bluedroid_enable();
  if (err != ESP_OK) {
    LOG(LL_ERROR, ("bluedroid enable failed: %d", err));
    goto out;
  }

  esp_ble_gap_register_callback(esp32_bt_gap_ev);

  if (!esp32_bt_gattc_init()) {
    LOG(LL_ERROR, ("GATTC init failed"));
    ret = false;
  }

  if (!esp32_bt_gatts_init()) {
    LOG(LL_ERROR, ("GATTS init failed"));
    ret = false;
  }

  LOG(LL_INFO, ("Bluetooth init ok"));
  ret = true;

out:
  return ret;
}
