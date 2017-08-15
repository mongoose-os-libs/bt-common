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
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"

#include "common/cs_dbg.h"
#include "common/queue.h"

#include "mgos_hal.h"

#define INVALID_ESP_CONNECTION_ID ((uint16_t) 0xffff)

struct esp32_gattc_list_svcs_ctx;
struct esp32_gattc_list_chars_ctx;
struct esp32_gattc_read_char_ctx;
struct esp32_gattc_write_char_ctx;

struct esp32_gattc_connection_entry {
  int conn_id;
  struct esp32_bt_connection bc;
  mgos_bt_gattc_open_cb open_cb;
  void *open_cb_arg;
  struct esp32_gattc_list_svcs_ctx *ls_ctx;
  struct esp32_gattc_list_chars_ctx *lc_ctx;
  STAILQ_HEAD(read_reqs, esp32_gattc_read_char_ctx) read_reqs;
  STAILQ_HEAD(write_reqs, esp32_gattc_write_char_ctx) write_reqs;
  SLIST_ENTRY(esp32_gattc_connection_entry) next;
};

struct esp32_gattc_list_svcs_ctx {
  int conn_id;
  int num_res;
  esp_gatt_srvc_id_t *res;
  mgos_bt_gattc_list_services_cb_t cb;
  void *cb_arg;
};

struct esp32_gattc_list_chars_ctx {
  int conn_id;
  esp_gatt_srvc_id_t svc_id;
  int num_res;
  struct mgos_bt_gattc_list_chars_result *res;
  mgos_bt_gattc_list_chars_cb_t cb;
  void *cb_arg;
};

struct esp32_gattc_read_char_ctx {
  int conn_id;
  esp_gatt_srvc_id_t svc_id;
  esp_gatt_id_t char_id;
  int value_len;
  uint8_t *value;
  mgos_bt_gattc_read_char_cb_t cb;
  void *cb_arg;
  STAILQ_ENTRY(esp32_gattc_read_char_ctx) next;
};

struct esp32_gattc_write_char_ctx {
  int conn_id;
  esp_gatt_srvc_id_t svc_id;
  esp_gatt_id_t char_id;
  bool success;
  mgos_bt_gattc_write_char_cb_t cb;
  void *cb_arg;
  STAILQ_ENTRY(esp32_gattc_write_char_ctx) next;
};

static SLIST_HEAD(s_conns, esp32_gattc_connection_entry) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static int s_conn_id = 0;
static esp_gatt_if_t s_gattc_if = 0;

static struct esp32_gattc_connection_entry *find_connection_by_addr(
    const esp_bd_addr_t addr, bool pending) {
  struct esp32_gattc_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->bc.gatt_if == s_gattc_if &&
        mgos_bt_addr_cmp(ce->bc.peer_addr, addr) == 0 &&
        (!pending || ce->bc.conn_id == INVALID_ESP_CONNECTION_ID)) {
      return ce;
    }
  }
  return NULL;
}

static struct esp32_gattc_connection_entry *find_connection_by_esp_conn_id(
    uint16_t esp_conn_id) {
  struct esp32_gattc_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->bc.gatt_if == s_gattc_if && ce->bc.conn_id == esp_conn_id)
      return ce;
  }
  return NULL;
}

static struct esp32_gattc_connection_entry *find_connection_by_id(int id) {
  struct esp32_gattc_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->conn_id == id) return ce;
  }
  return NULL;
}

static void ls_done(struct esp32_gattc_connection_entry *ce);
static void lc_done(struct esp32_gattc_connection_entry *ce);
static void read_done(struct esp32_gattc_connection_entry *ce,
                      struct esp32_gattc_read_char_ctx *rc);
static void write_done(struct esp32_gattc_connection_entry *ce,
                       struct esp32_gattc_write_char_ctx *rc);

static void remove_connection(struct esp32_gattc_connection_entry *ce) {
  if (ce->ls_ctx != NULL) ls_done(ce);
  SLIST_REMOVE(&s_conns, ce, esp32_gattc_connection_entry, next);
  free(ce);
}

static void esp32_bt_gattc_ev(esp_gattc_cb_event_t ev, esp_gatt_if_t gattc_if,
                              esp_ble_gattc_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN], buf2[BT_UUID_STR_LEN], buf3[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GATTC_REG_EVT: {
      const struct gattc_reg_evt_param *p = &ep->reg;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG if %d st %d app %d", gattc_if, p->status, p->app_id));
      if (p->status != ESP_GATT_OK) break;
      s_gattc_if = gattc_if;
      break;
    }
    case ESP_GATTC_UNREG_EVT: {
      LOG(LL_DEBUG, ("UNREG"));
      break;
    }
    case ESP_GATTC_OPEN_EVT: {
      const struct gattc_open_evt_param *p = &ep->open;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("OPEN st %d cid %d addr %s mtu %d", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf), p->mtu));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_addr(p->remote_bda, true /* pending */);
      if (ce == NULL) break;
      ce->bc.conn_id = p->conn_id;
      if (p->status != ESP_GATT_OK) {
        ce->open_cb(ce->conn_id, false, ce->open_cb_arg);
        remove_connection(ce);
        break;
      }
      if (p->mtu != ce->bc.mtu) {
        LOG(LL_DEBUG, ("Setting MTU to %d", ce->bc.mtu));
        if (esp_ble_gattc_config_mtu(gattc_if, p->conn_id, ce->bc.mtu) !=
            ESP_OK) {
          ce->open_cb(ce->conn_id, false, ce->open_cb_arg);
          esp_ble_gattc_close(gattc_if, p->conn_id);
        }
      } else {
        ce->open_cb(ce->conn_id, true, ce->open_cb_arg);
      }
      break;
    }
    case ESP_GATTC_READ_CHAR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("READ st %d cid %d svc %s char %s val_type 0x%x val_len %d",
           p->status, p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
           mgos_bt_uuid_to_str(&p->char_id.uuid, buf2), p->value_type,
           p->value_len));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      struct esp32_gattc_read_char_ctx *rc;
      STAILQ_FOREACH(rc, &ce->read_reqs, next) {
        if (mgos_bt_uuid_cmp(&p->srvc_id.id.uuid, &rc->svc_id.id.uuid) == 0 &&
            mgos_bt_uuid_cmp(&p->char_id.uuid, &rc->char_id.uuid) == 0) {
          break;
        }
      }
      if (rc != NULL) {
        if (p->status == ESP_GATT_OK) {
          rc->value_len = p->value_len;
          rc->value = malloc(rc->value_len);
          if (rc->value != NULL) {
            memcpy(rc->value, p->value, rc->value_len);
          } else {
            rc->value_len = -4;
          }
        } else {
          rc->value_len = -5;
        }
        read_done(ce, rc);
      }
      break;
    }
    case ESP_GATTC_WRITE_CHAR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("WRITE st %d cid %d svc %s char %s", p->status, p->conn_id,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      struct esp32_gattc_write_char_ctx *wc;
      STAILQ_FOREACH(wc, &ce->write_reqs, next) {
        if (mgos_bt_uuid_cmp(&p->srvc_id.id.uuid, &wc->svc_id.id.uuid) == 0 &&
            mgos_bt_uuid_cmp(&p->char_id.uuid, &wc->char_id.uuid) == 0) {
          break;
        }
      }
      if (wc != NULL) {
        wc->success = (p->status == ESP_GATT_OK);
        write_done(ce, wc);
      }
      break;
    }
    case ESP_GATTC_CLOSE_EVT: {
      const struct gattc_close_evt_param *p = &ep->close;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CLOSE st %d cid %d addr %s reason %d", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf), p->reason));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      remove_connection(ce);
      break;
    }
    case ESP_GATTC_SEARCH_RES_EVT: {
      const struct gattc_search_res_evt_param *p = &ep->search_res;
      LOG(LL_DEBUG,
          ("SEARCH_RES cid %d svc %s %d%s", p->conn_id,
           mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf), p->srvc_id.id.inst_id,
           (p->srvc_id.is_primary ? " primary" : "")));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      struct esp32_gattc_list_svcs_ctx *ls_ctx = ce->ls_ctx;
      if (ls_ctx == NULL) break;
      ls_ctx->res =
          realloc(ls_ctx->res, (ls_ctx->num_res + 1) * sizeof(*ls_ctx->res));
      if (ls_ctx->res != NULL) {
        memcpy(&ls_ctx->res[ls_ctx->num_res], &p->srvc_id,
               sizeof(*ls_ctx->res));
        ls_ctx->num_res++;
      } else {
        ls_ctx->num_res = 0;
      }
      break;
    }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      const struct gattc_search_cmpl_evt_param *p = &ep->search_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SEARCH_CMPL st %d cid %d", p->status, p->conn_id));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      ls_done(ce);
      break;
    }
    case ESP_GATTC_READ_DESCR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("READ_DESCR st %d cid %d svc %s descr %s val_type 0x%x val_len %d",
           p->status, p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
           mgos_bt_uuid_to_str(&p->descr_id.uuid, buf2), p->value_type,
           p->value_len));
      break;
    }
    case ESP_GATTC_WRITE_DESCR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("WRITE_DESCR st %d cid %d svc %s char %s", p->status, p->conn_id,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
      const struct gattc_notify_evt_param *p = &ep->notify;
      LOG(LL_DEBUG,
          ("%s cid %d addr %s svc %s char %s val_len %d",
           (p->is_notify ? "NOTIFY" : "INDICATE"), p->conn_id,
           mgos_bt_addr_to_str(p->remote_bda, buf),
           mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf2),
           mgos_bt_uuid_to_str(&p->char_id.uuid, buf3), p->value_len));
      break;
    }
    case ESP_GATTC_PREP_WRITE_EVT: {
      LOG(LL_DEBUG, ("PREP_WRITE"));
      break;
    }
    case ESP_GATTC_EXEC_EVT: {
      const struct gattc_exec_cmpl_evt_param *p = &ep->exec_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("EXEC st %d cid %d", p->status, p->conn_id));
      break;
    }
    case ESP_GATTC_ACL_EVT: {
      LOG(LL_DEBUG, ("ACL"));
      break;
    }
    case ESP_GATTC_CANCEL_OPEN_EVT: {
      LOG(LL_DEBUG, ("CANCEL_OPEN"));
      break;
    }
    case ESP_GATTC_SRVC_CHG_EVT: {
      const struct gattc_srvc_chg_evt_param *p = &ep->srvc_chg;
      LOG(LL_DEBUG, ("SRVC_CHG %s", mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_ENC_CMPL_CB_EVT: {
      LOG(LL_DEBUG, ("ENC_CMPL"));
      break;
    }
    case ESP_GATTC_CFG_MTU_EVT: {
      const struct gattc_cfg_mtu_evt_param *p = &ep->cfg_mtu;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CFG_MTU st %d cid %d mtu %d", p->status, p->conn_id, p->mtu));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      ce->bc.mtu = p->mtu;
      ce->open_cb(ce->conn_id, (p->status == ESP_GATT_OK), ce->open_cb_arg);
      break;
    }
    case ESP_GATTC_ADV_DATA_EVT: {
      LOG(LL_DEBUG, ("ADV_DATA"));
      break;
    }
    case ESP_GATTC_MULT_ADV_ENB_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_ENB"));
      break;
    }
    case ESP_GATTC_MULT_ADV_UPD_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_UPD"));
      break;
    }
    case ESP_GATTC_MULT_ADV_DATA_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_DATA"));
      break;
    }
    case ESP_GATTC_MULT_ADV_DIS_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_DIS"));
      break;
    }
    case ESP_GATTC_CONGEST_EVT: {
      const struct gattc_congest_evt_param *p = &ep->congest;
      LOG(LL_DEBUG,
          ("CONGEST cid %d%s", p->conn_id, (p->congested ? " congested" : "")));
      break;
    }
    case ESP_GATTC_BTH_SCAN_ENB_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_ENB"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_CFG_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_CFG"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_RD_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_RD"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_THR_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_THR"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_PARAM_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_PARAM"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_DIS_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_DIS"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_CFG_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_CFG"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_PARAM_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_PARAM"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_STATUS_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_STATUS"));
      break;
    }
    case ESP_GATTC_ADV_VSC_EVT: {
      LOG(LL_DEBUG, ("SCAN_ADV_VSC"));
      break;
    }
    case ESP_GATTC_GET_CHAR_EVT: {
      struct gattc_get_char_evt_param *p = &ep->get_char;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_CHAR st %d cid %d svc %s char %s prop %02x", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2), p->char_prop));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      /* When there are no more characteristics to list we get ESP_GATT_ERROR */
      if (p->status != ESP_GATT_OK) {
        lc_done(ce);
        break;
      }
      struct esp32_gattc_list_chars_ctx *lc_ctx = ce->lc_ctx;
      if (lc_ctx == NULL) break;
      lc_ctx->res =
          realloc(lc_ctx->res, (lc_ctx->num_res + 1) * sizeof(*lc_ctx->res));
      if (lc_ctx->res != NULL) {
        struct mgos_bt_gattc_list_chars_result *res =
            &lc_ctx->res[lc_ctx->num_res];
        memcpy(&res->char_id, &p->char_id, sizeof(res->char_id));
        res->char_prop = p->char_prop;
        lc_ctx->num_res++;
      } else {
        lc_ctx->num_res = 0;
      }
      esp_ble_gattc_get_characteristic(ce->bc.gatt_if, ce->bc.conn_id,
                                       &lc_ctx->svc_id, &p->char_id);
      break;
    }
    case ESP_GATTC_GET_DESCR_EVT: {
      const struct gattc_get_descr_evt_param *p = &ep->get_descr;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_DESCR st %d cid %d svc %s char %s descr %s", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2),
               mgos_bt_uuid_to_str(&p->descr_id.uuid, buf3)));
      break;
    }
    case ESP_GATTC_GET_INCL_SRVC_EVT: {
      const struct gattc_get_incl_srvc_evt_param *p = &ep->get_incl_srvc;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_INCL_SRVC st %d cid %d svc %s incl_svc %s", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->incl_srvc_id.id.uuid, buf)));
      break;
    }
    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      const struct gattc_reg_for_notify_evt_param *p = &ep->reg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG_FOR_NOTIFY st %d svc %s char %s", p->status,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_UNREG_FOR_NOTIFY_EVT: {
      const struct gattc_unreg_for_notify_evt_param *p = &ep->unreg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("UNREG_FOR_NOTIFY st %d svc %s char %s", p->status,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_CONNECT_EVT: {
      const struct gattc_connect_evt_param *p = &ep->connect;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CONNECT st %d cid %d addr %s", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT: {
      const struct gattc_disconnect_evt_param *p = &ep->disconnect;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("DISCONNECT st %d cid %d addr %s", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
  }
}

static void gattc_open_scan_cb(int num_res,
                               const struct mgos_bt_ble_scan_result *res,
                               void *arg) {
  char buf[BT_ADDR_STR_LEN];
  struct esp32_gattc_connection_entry *ce =
      (struct esp32_gattc_connection_entry *) arg;
  if (num_res <= 0) {
    LOG(LL_ERROR, ("%s not found (%d)",
                   mgos_bt_addr_to_str(ce->bc.peer_addr, buf), num_res));
    ce->open_cb(ce->conn_id, false, ce->open_cb_arg);
    remove_connection(ce);
    return;
  }
  LOG(LL_INFO, ("%s found, RSSI %d", mgos_bt_addr_to_str(ce->bc.peer_addr, buf),
                res->rssi));
  if (esp_ble_gattc_open(ce->bc.gatt_if, ce->bc.peer_addr,
                         true /* is_direct */) != ESP_OK) {
    ce->open_cb(ce->conn_id, false, ce->open_cb_arg);
    remove_connection(ce);
  }
}

void mgos_bt_gattc_open(const esp_bd_addr_t addr, int mtu,
                        mgos_bt_gattc_open_cb cb, void *cb_arg) {
  char buf[BT_ADDR_STR_LEN];
  struct esp32_gattc_connection_entry *ce =
      find_connection_by_addr(addr, false /* pending */);
  if (ce != NULL) {
    /*
     * Note: ESP GATTC API seems to imply that multiple connections to the same
     * address should be possible, but in reality it's not.
     * Subsequent esp_ble_gattc_open() calls just do nothing.
     * There also seems to be no support for multiple in-flight commands
     * (no transaction id in the result gattc_read_char_evt_param).
     * Right now, we just disallow mgos_bt_gattc_connect attempts when there's
     * already a connection.
     * TODO(rojer): Figure it out.
     */
    LOG(LL_ERROR, ("Multiple BLE connections to the same address are not "
                   "supported (conn_id %d)",
                   ce->conn_id));
    cb(ce->conn_id, false, cb_arg);
    return;
  }
  ce = (struct esp32_gattc_connection_entry *) calloc(1, sizeof(*ce));
  if (ce == NULL) return;
  ce->conn_id = s_conn_id++;
  ce->bc.conn_id = INVALID_ESP_CONNECTION_ID;
  ce->bc.gatt_if = s_gattc_if;
  ce->bc.mtu = (mtu > 0 ? mtu : ESP_GATT_DEF_BLE_MTU_SIZE);
  memcpy(ce->bc.peer_addr, addr, ESP_BD_ADDR_LEN);
  ce->open_cb = cb;
  ce->open_cb_arg = cb_arg;
  STAILQ_INIT(&ce->read_reqs);
  STAILQ_INIT(&ce->write_reqs);
  SLIST_INSERT_HEAD(&s_conns, ce, next);
  if (is_advertising()) esp_ble_gap_stop_advertising();
  /* Due to https://github.com/espressif/esp-idf/issues/908 we cannot call
   * esp_ble_gattc_open right away and have to scan for the device first. */
  LOG(LL_INFO, ("Looking for %s", mgos_bt_addr_to_str(ce->bc.peer_addr, buf)));
  mgos_bt_ble_scan_device(ce->bc.peer_addr, gattc_open_scan_cb, ce);
}

static void ls_done_mgos_cb(void *arg) {
  struct esp32_gattc_list_svcs_ctx *ls_ctx =
      (struct esp32_gattc_list_svcs_ctx *) arg;
  ls_ctx->cb(ls_ctx->conn_id, ls_ctx->num_res, ls_ctx->res, ls_ctx->cb_arg);
  free(ls_ctx->res);
  free(ls_ctx);
}

static void ls_done(struct esp32_gattc_connection_entry *ce) {
  struct esp32_gattc_list_svcs_ctx *ls_ctx = ce->ls_ctx;
  if (ls_ctx == NULL) return;
  ce->ls_ctx = NULL;
  mgos_invoke_cb(ls_done_mgos_cb, ls_ctx, false /* from_isr */);
}

void mgos_bt_gattc_list_services(int conn_id,
                                 mgos_bt_gattc_list_services_cb_t cb,
                                 void *cb_arg) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) {
    cb(conn_id, -1, NULL, cb_arg);
    return;
  }
  struct esp32_gattc_list_svcs_ctx *ls_ctx = calloc(1, sizeof(*ls_ctx));
  if (ls_ctx == NULL) {
    cb(conn_id, -2, NULL, cb_arg);
    return;
  }
  ls_ctx->conn_id = ce->conn_id;
  ls_ctx->cb = cb;
  ls_ctx->cb_arg = cb_arg;
  if (ce->ls_ctx == NULL) {
    ce->ls_ctx = ls_ctx;
    if (esp_ble_gattc_search_service(ce->bc.gatt_if, ce->bc.conn_id, NULL) !=
        ESP_OK) {
      ls_ctx->num_res = -1;
      ls_done(ce);
    }
  } else {
    ls_ctx->num_res = -1;
    mgos_invoke_cb(ls_done_mgos_cb, ls_ctx, false /* from_isr */);
  }
}

static void lc_done_mgos_cb(void *arg) {
  struct esp32_gattc_list_chars_ctx *lc_ctx =
      (struct esp32_gattc_list_chars_ctx *) arg;
  lc_ctx->cb(lc_ctx->conn_id, &lc_ctx->svc_id, lc_ctx->num_res, lc_ctx->res,
             lc_ctx->cb_arg);
  free(lc_ctx->res);
  free(lc_ctx);
}

static void lc_done(struct esp32_gattc_connection_entry *ce) {
  struct esp32_gattc_list_chars_ctx *lc_ctx = ce->lc_ctx;
  if (lc_ctx == NULL) return;
  ce->lc_ctx = NULL;
  mgos_invoke_cb(lc_done_mgos_cb, lc_ctx, false /* from_isr */);
}

void mgos_bt_gattc_list_chars(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                              mgos_bt_gattc_list_chars_cb_t cb, void *cb_arg) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) {
    cb(conn_id, svc_id, -1, NULL, cb_arg);
    return;
  }
  struct esp32_gattc_list_chars_ctx *lc_ctx = calloc(1, sizeof(*lc_ctx));
  if (lc_ctx == NULL) {
    cb(conn_id, svc_id, -2, NULL, cb_arg);
    return;
  }
  lc_ctx->conn_id = ce->conn_id;
  memcpy(&lc_ctx->svc_id, svc_id, sizeof(lc_ctx->svc_id));
  lc_ctx->cb = cb;
  lc_ctx->cb_arg = cb_arg;
  if (ce->lc_ctx == NULL) {
    ce->lc_ctx = lc_ctx;
    if (esp_ble_gattc_get_characteristic(ce->bc.gatt_if, ce->bc.conn_id,
                                         &lc_ctx->svc_id, NULL) != ESP_OK) {
      lc_ctx->num_res = -1;
      lc_done(ce);
    }
  } else {
    lc_ctx->num_res = -1;
    mgos_invoke_cb(lc_done_mgos_cb, lc_ctx, false /* from_isr */);
  }
}

static void read_done_mgos_cb(void *arg) {
  struct esp32_gattc_read_char_ctx *rc =
      (struct esp32_gattc_read_char_ctx *) arg;
  if (rc->value_len < 0) {
    rc->cb(rc->conn_id, false, mg_mk_str(NULL), rc->cb_arg);
  } else {
    rc->cb(rc->conn_id, true,
           mg_mk_str_n((const char *) rc->value, rc->value_len), rc->cb_arg);
  }
  free(rc->value);
  free(rc);
}

static void read_done(struct esp32_gattc_connection_entry *ce,
                      struct esp32_gattc_read_char_ctx *rc) {
  STAILQ_REMOVE(&ce->read_reqs, rc, esp32_gattc_read_char_ctx, next);
  mgos_invoke_cb(read_done_mgos_cb, rc, false /* from_isr */);
}

void mgos_bt_gattc_read_char(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                             const esp_gatt_id_t *char_id,
                             esp_gatt_auth_req_t auth_req,
                             mgos_bt_gattc_read_char_cb_t cb, void *cb_arg) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) {
    cb(conn_id, false, mg_mk_str(NULL), cb_arg);
    return;
  }
  struct esp32_gattc_read_char_ctx *rc = calloc(1, sizeof(*rc));
  if (rc == NULL) {
    cb(conn_id, false, mg_mk_str(NULL), cb_arg);
    return;
  }
  rc->conn_id = conn_id;
  memcpy(&rc->svc_id, svc_id, sizeof(rc->svc_id));
  memcpy(&rc->char_id, char_id, sizeof(rc->char_id));
  rc->cb = cb;
  rc->cb_arg = cb_arg;
  STAILQ_INSERT_TAIL(&ce->read_reqs, rc, next);
  if (esp_ble_gattc_read_char(ce->bc.gatt_if, ce->bc.conn_id, &rc->svc_id,
                              &rc->char_id, auth_req) != ESP_OK) {
    rc->value_len = -3;
    read_done(ce, rc);
  }
}

static void write_done_mgos_cb(void *arg) {
  struct esp32_gattc_write_char_ctx *wc =
      (struct esp32_gattc_write_char_ctx *) arg;
  wc->cb(wc->conn_id, wc->success, wc->cb_arg);
  free(wc);
}

static void write_done(struct esp32_gattc_connection_entry *ce,
                       struct esp32_gattc_write_char_ctx *wc) {
  STAILQ_REMOVE(&ce->write_reqs, wc, esp32_gattc_write_char_ctx, next);
  mgos_invoke_cb(write_done_mgos_cb, wc, false /* from_isr */);
}

void mgos_bt_gattc_write_char(int conn_id, const esp_gatt_srvc_id_t *svc_id,
                              const esp_gatt_id_t *char_id,
                              bool response_required,
                              esp_gatt_auth_req_t auth_req,
                              const struct mg_str value,
                              mgos_bt_gattc_write_char_cb_t cb, void *cb_arg) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) {
    cb(conn_id, false, cb_arg);
    return;
  }
  struct esp32_gattc_write_char_ctx *wc = calloc(1, sizeof(*wc));
  if (wc == NULL) {
    cb(conn_id, false, cb_arg);
    return;
  }
  wc->conn_id = conn_id;
  memcpy(&wc->svc_id, svc_id, sizeof(wc->svc_id));
  memcpy(&wc->char_id, char_id, sizeof(wc->char_id));
  wc->cb = cb;
  wc->cb_arg = cb_arg;
  STAILQ_INSERT_TAIL(&ce->write_reqs, wc, next);
  if (esp_ble_gattc_write_char(ce->bc.gatt_if, ce->bc.conn_id, &wc->svc_id,
                               &wc->char_id, value.len, (uint8_t *) value.p,
                               (response_required ? ESP_GATT_WRITE_TYPE_RSP
                                                  : ESP_GATT_WRITE_TYPE_NO_RSP),
                               auth_req) != ESP_OK) {
    wc->success = false;
    write_done(ce, wc);
  }
}

void mgos_bt_gattc_close(int conn_id) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL || ce->bc.conn_id == INVALID_ESP_CONNECTION_ID) return;
  esp_ble_gattc_close(ce->bc.gatt_if, ce->bc.conn_id);
}

bool esp32_bt_gattc_init(void) {
  return (esp_ble_gattc_register_callback(esp32_bt_gattc_ev) == ESP_OK &&
          esp_ble_gattc_app_register(0) == ESP_OK);
}
