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

#include "mgos_net.h"
#include "mgos_sys_config.h"

static bool s_advertising = false;

static esp_ble_adv_params_t mos_adv_params = {
    .adv_int_min = 0x100, /* 0x100 * 0.625 = 100 ms */
    .adv_int_max = 0x200, /* 0x200 * 0.625 = 200 ms */
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
    .scan_window = 0x50,    /* 0x50 * 0.625 = 50 ms */
};

struct cb_info {
  void *cb;
  void *arg;
  SLIST_ENTRY(cb_info) next;
};
static SLIST_HEAD(s_scan_cbs, cb_info) s_scan_cbs;
static bool s_scan_in_progress = false;
static struct mgos_bt_ble_scan_result *s_scan_results = NULL;
static int s_num_scan_results = 0;

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
  return s_scan_in_progress;
}

static void mgos_bt_ble_scan_done(int num_res,
                                  struct mgos_bt_ble_scan_result *res) {
  s_scan_in_progress = false;
  s_scan_results = NULL;
  s_num_scan_results = 0;
  LOG(LL_INFO, ("BLE scan done, %d", num_res));
  if (get_cfg()->bt.adv_enable && !is_advertising()) { /* Resume advertising */
    start_advertising();
  }
  SLIST_HEAD(scan_cbs, cb_info) scan_cbs;
  memcpy(&scan_cbs, &s_scan_cbs, sizeof(scan_cbs));
  memset(&s_scan_cbs, 0, sizeof(s_scan_cbs));
  struct cb_info *cbi, *cbit;
  SLIST_FOREACH_SAFE(cbi, &scan_cbs, next, cbit) {
    ((mgos_bt_ble_scan_cb_t) cbi->cb)(num_res, res, cbi->arg);
    free(cbi);
  }
  free(res);
}

static void esp32_bt_gap_ev(esp_gap_ble_cb_event_t ev,
                            esp_ble_gap_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT: {
      const struct ble_adv_data_cmpl_evt_param *p = &ep->adv_data_cmpl;
      LOG(LL_DEBUG, ("ADV_DATA_SET_COMPLETE st %d", p->status));
      if (get_cfg()->bt.adv_enable && !is_scanning()) {
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
        mgos_bt_ble_scan_done(-2, NULL);
        break;
      }
      /*
       * Scanning and advertising is incompatible.
       * If we are advertising, suspend to perform a scan.
       */
      if (s_advertising) {
        if (esp_ble_gap_stop_advertising() != ESP_OK) {
          mgos_bt_ble_scan_done(-3, NULL);
        }
      } else {
        if (esp_ble_gap_start_scanning(MGOS_BT_BLE_SCAN_DURATION) != ESP_OK) {
          mgos_bt_ble_scan_done(-4, NULL);
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
          for (int i = 0; i < s_num_scan_results; i++) {
            if (memcmp(&s_scan_results[i].addr, &p->bda, sizeof(p->bda)) == 0) {
              r = &s_scan_results[i];
              break;
            }
          }
          if (r == NULL) {
            s_num_scan_results++;
            s_scan_results =
                realloc(s_scan_results, s_num_scan_results * sizeof(*r));
            r = &s_scan_results[s_num_scan_results - 1];
          }
          memset(r, 0, sizeof(*r));
          memcpy(&r->addr, &p->bda, sizeof(r->addr));
          memcpy(r->name, name, name_len);
          r->rssi = p->rssi;
          break;
        }
        case ESP_GAP_SEARCH_INQ_CMPL_EVT: {
          LOG(LL_DEBUG, ("SCAN_COMPLETE %d", s_num_scan_results));
          mgos_bt_ble_scan_done(s_num_scan_results, s_scan_results);
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
        mgos_bt_ble_scan_done(-3, NULL);
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
          mgos_bt_ble_scan_done(-5, NULL);
        }
      }
      break;
    }
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT: {
      const struct ble_scan_stop_cmpl_evt_param *p = &ep->scan_stop_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SCAN_STOP_COMPLETE st %d", p->status));
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
  }
}

void mgos_bt_ble_scan(mgos_bt_ble_scan_cb_t cb, void *arg) {
  struct cb_info *cbi = (struct cb_info *) calloc(1, sizeof(*cbi));
  if (cbi == NULL) return;
  cbi->cb = cb;
  cbi->arg = arg;
  SLIST_INSERT_HEAD(&s_scan_cbs, cbi, next);
  if (!s_scan_in_progress) {
    s_scan_in_progress = true;
    if (esp_ble_gap_set_scan_params(&ble_scan_params) != ESP_OK) {
      mgos_bt_ble_scan_done(-1, NULL);
    }
  }
}

static void mgos_bt_net_ev(enum mgos_net_event ev,
                           const struct mgos_net_event_data *ev_data,
                           void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  LOG(LL_INFO, ("Network is up, disabling Bluetooth"));
  get_cfg()->bt.enable = false;
  char *msg = NULL;
  if (save_cfg(get_cfg(), &msg)) {
    esp_bt_controller_disable(ESP_BT_MODE_BTDM);
  }
  (void) arg;
}

bool mgos_bt_common_init(void) {
  bool ret = false;
  const struct sys_config *cfg = get_cfg();
  const struct sys_config_bt *btcfg = &cfg->bt;
  if (!btcfg->enable) {
    LOG(LL_INFO, ("Bluetooth is disabled"));
    return true;
  }

  if (!btcfg->keep_enabled) {
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
