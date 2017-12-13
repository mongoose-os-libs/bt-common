/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#include "esp32_bt_gattc.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "bta_api.h"
#include "esp_bt.h"
#include "esp_bt_defs.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_common_api.h"
#include "esp_gattc_api.h"

#include "common/cs_dbg.h"
#include "common/queue.h"

#include "mgos_system.h"

#include "esp32_bt_internal.h"

#define INVALID_ESP_CONNECTION_ID ((uint16_t) 0xffff)

struct esp32_gattc_open_ctx;
struct esp32_gattc_list_svcs_ctx;
struct esp32_gattc_read_char_ctx;
struct esp32_gattc_write_char_ctx;
struct esp32_gattc_subscribe_ctx;

struct esp32_gattc_connection_entry {
  int conn_id;
  bool mtu_set;
  bool services_listed;
  struct esp32_bt_connection bc;
  struct esp32_gattc_open_ctx *open_ctx;
  struct esp32_gattc_list_svcs_ctx *ls_ctx;
  STAILQ_HEAD(read_reqs, esp32_gattc_read_char_ctx) read_reqs;
  STAILQ_HEAD(write_reqs, esp32_gattc_write_char_ctx) write_reqs;
  STAILQ_HEAD(subscriptions, esp32_gattc_subscribe_ctx) subscriptions;
  SLIST_ENTRY(esp32_gattc_connection_entry) next;
};

struct esp32_gattc_open_ctx {
  uint16_t conn_id;
  bool result;
  mgos_bt_gattc_open_cb cb;
  void *cb_arg;
};

struct esp32_gattc_list_svcs_ctx {
  int conn_id;
  int num_res;
  esp_gatt_srvc_id_t *res;
  mgos_bt_gattc_list_services_cb_t cb;
  void *cb_arg;
};

struct esp32_gattc_read_char_ctx {
  int conn_id;
  esp_bt_uuid_t svc_uuid;
  esp_bt_uuid_t char_uuid;
  uint16_t handle;
  int value_len;
  uint8_t *value;
  mgos_bt_gattc_read_char_cb_t cb;
  void *cb_arg;
  STAILQ_ENTRY(esp32_gattc_read_char_ctx) next;
};

struct esp32_gattc_write_char_ctx {
  int conn_id;
  esp_bt_uuid_t svc_uuid;
  esp_bt_uuid_t char_uuid;
  uint16_t handle;
  bool success;
  mgos_bt_gattc_write_char_cb_t cb;
  void *cb_arg;
  STAILQ_ENTRY(esp32_gattc_write_char_ctx) next;
};

struct esp32_gattc_subscribe_ctx {
  int conn_id;
  esp_bt_uuid_t svc_uuid;
  esp_bt_uuid_t char_uuid;
  uint16_t handle;
  uint16_t cccd_handle;
  bool success;
  uint8_t *values; /* a sequnce of len/value, len/value...; len is U16LE */
  uint16_t values_len;
  mgos_bt_gattc_subscribe_cb_t cb;
  void *cb_arg;
  STAILQ_ENTRY(esp32_gattc_subscribe_ctx) next;
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

static struct esp32_gattc_connection_entry *find_connection_by_id(int conn_id) {
  struct esp32_gattc_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->conn_id == conn_id) return ce;
  }
  return NULL;
}

static void ls_done(struct esp32_gattc_connection_entry *ce);
static void read_done_mgos_cb(void *arg);
static void write_done_mgos_cb(void *arg);
static void subscribe_mgos_cb(void *arg);

static void open_done_mgos_cb(void *arg) {
  struct esp32_gattc_open_ctx *octx = (struct esp32_gattc_open_ctx *) arg;
  octx->cb(octx->conn_id, octx->result, octx->cb_arg);
  free(octx);
}

static void open_done(struct esp32_gattc_connection_entry *ce, bool result) {
  struct esp32_gattc_open_ctx *oc = ce->open_ctx;
  if (oc == NULL) return;
  oc->result = result;
  ce->open_ctx = NULL;
  mgos_invoke_cb(open_done_mgos_cb, oc, false /* from_isr */);
}

static void remove_connection(struct esp32_gattc_connection_entry *ce) {
  if (ce->ls_ctx != NULL) ls_done(ce);
  if (ce->open_ctx != NULL) open_done(ce, false);
  SLIST_REMOVE(&s_conns, ce, esp32_gattc_connection_entry, next);
  free(ce);
}

static void esp32_bt_gattc_ev(esp_gattc_cb_event_t ev, esp_gatt_if_t gattc_if,
                              esp_ble_gattc_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN], buf2[BT_UUID_STR_LEN];
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
      LOG(ll, ("OPEN st %d cid %u addr %s mtu %d", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf), p->mtu));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_addr(p->remote_bda, true /* pending */);
      if (ce == NULL) break;
      ce->bc.conn_id = p->conn_id;
      if (p->status != ESP_GATT_OK) {
        open_done(ce, false);
        remove_connection(ce);
        break;
      }
      ce->bc.mtu = p->mtu;
      /*
       * Perform automatic service discovery.
       * This is needed for UUID lookups to work.
       */
      if (esp_ble_gattc_search_service(ce->bc.gatt_if, ce->bc.conn_id, NULL) !=
          ESP_OK) {
        open_done(ce, false);
        esp_ble_gattc_close(gattc_if, p->conn_id);
      }
      break;
    }
    case ESP_GATTC_READ_CHAR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("READ st %d cid %u h %u val_len %u", p->status, p->conn_id,
               p->handle, p->value_len));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      struct esp32_gattc_read_char_ctx *rc;
      STAILQ_FOREACH(rc, &ce->read_reqs, next) {
        if (rc->handle == p->handle) break;
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
        STAILQ_REMOVE(&ce->read_reqs, rc, esp32_gattc_read_char_ctx, next);
        mgos_invoke_cb(read_done_mgos_cb, rc, false /* from_isr */);
      }
      break;
    }
    case ESP_GATTC_WRITE_CHAR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("WRITE st %d cid %u h %u", p->status, p->conn_id, p->handle));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      struct esp32_gattc_write_char_ctx *wc;
      STAILQ_FOREACH(wc, &ce->write_reqs, next) {
        if (wc->handle == p->handle) break;
      }
      if (wc != NULL) {
        wc->success = (p->status == ESP_GATT_OK);
        STAILQ_REMOVE(&ce->write_reqs, wc, esp32_gattc_write_char_ctx, next);
        mgos_invoke_cb(write_done_mgos_cb, wc, false /* from_isr */);
      }
      break;
    }
    case ESP_GATTC_CLOSE_EVT: {
      const struct gattc_close_evt_param *p = &ep->close;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CLOSE st %d cid %u addr %s reason %d", p->status, p->conn_id,
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
          ("SEARCH_RES cid %u svc %s %d", p->conn_id,
           mgos_bt_uuid_to_str(&p->srvc_id.uuid, buf), p->srvc_id.inst_id));
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
      LOG(ll, ("SEARCH_CMPL st %d cid %u", p->status, p->conn_id));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      if (p->status == ESP_GATT_OK) ce->services_listed = true;
      if (ce->open_ctx != NULL) {
        if (p->status == ESP_GATT_OK) {
          if (esp_ble_gattc_send_mtu_req(gattc_if, p->conn_id) != ESP_OK) {
            open_done(ce, false);
            esp_ble_gattc_close(gattc_if, p->conn_id);
          }
        } else {
          open_done(ce, false);
          esp_ble_gattc_close(gattc_if, p->conn_id);
        }
      }
      ls_done(ce);
      break;
    }
    case ESP_GATTC_READ_DESCR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("READ_DESCR st %d cid %u h %u val_len %u", p->status, p->conn_id,
               p->handle, p->value_len));
      break;
    }
    case ESP_GATTC_WRITE_DESCR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("WRITE_DESCR st %d cid %u h %u", p->status, p->conn_id, p->handle));
      struct esp32_gattc_connection_entry *ce = NULL;
      SLIST_FOREACH(ce, &s_conns, next) {
        struct esp32_gattc_subscribe_ctx *sc = NULL;
        STAILQ_FOREACH(sc, &ce->subscriptions, next) {
          if (sc->cccd_handle == p->handle) break;
        }
        if (sc == NULL) continue;
        sc->success = (p->status == ESP_GATT_OK);
        if (!sc->success) {
          STAILQ_REMOVE(&ce->subscriptions, sc, esp32_gattc_subscribe_ctx,
                        next);
        }
        mgos_invoke_cb(subscribe_mgos_cb, sc, false /* from_isr */);
      }
      break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
      const struct gattc_notify_evt_param *p = &ep->notify;
      LOG(LL_DEBUG,
          ("%s cid %u addr %s handle %u val_len %d",
           (p->is_notify ? "NOTIFY" : "INDICATE"), p->conn_id,
           mgos_bt_addr_to_str(p->remote_bda, buf), p->handle, p->value_len));
      struct esp32_gattc_connection_entry *ce = NULL;
      SLIST_FOREACH(ce, &s_conns, next) {
        struct esp32_gattc_subscribe_ctx *sc = NULL;
        STAILQ_FOREACH(sc, &ce->subscriptions, next) {
          if (sc->handle == p->handle) break;
        }
        if (sc == NULL) continue;
        uint16_t new_len = sc->values_len + 2 + p->value_len;
        uint8_t *new_values = realloc(sc->values, new_len);
        if (new_values == NULL) break;
        bool sched_cb = (sc->values == NULL);
        uint8_t *vp = new_values + sc->values_len;
        *vp++ = (p->value_len & 0xff);
        *vp++ = ((p->value_len >> 8) & 0xff);
        memcpy(vp, p->value, p->value_len);
        /* FIXME(rojer): Locking */
        sc->values = new_values;
        sc->values_len = new_len;
        if (sched_cb) {
          mgos_invoke_cb(subscribe_mgos_cb, sc, false /* from_isr */);
        }
      }
      break;
    }
    case ESP_GATTC_PREP_WRITE_EVT: {
      LOG(LL_DEBUG, ("PREP_WRITE"));
      break;
    }
    case ESP_GATTC_EXEC_EVT: {
      const struct gattc_exec_cmpl_evt_param *p = &ep->exec_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("EXEC st %d cid %u", p->status, p->conn_id));
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
      LOG(ll, ("CFG_MTU st %d cid %u mtu %d", p->status, p->conn_id, p->mtu));
      struct esp32_gattc_connection_entry *ce =
          find_connection_by_esp_conn_id(p->conn_id);
      if (ce == NULL) break;
      if (p->status == ESP_GATT_OK) {
        ce->mtu_set = true;
        ce->bc.mtu = p->mtu;
        if (ce->services_listed) open_done(ce, true);
      } else {
        open_done(ce, false);
      }
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
          ("CONGEST cid %u%s", p->conn_id, (p->congested ? " congested" : "")));
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
    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      const struct gattc_reg_for_notify_evt_param *p = &ep->reg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG_FOR_NOTIFY st %d h %u", p->status, p->handle));
      struct esp32_gattc_connection_entry *ce = NULL;
      SLIST_FOREACH(ce, &s_conns, next) {
        struct esp32_gattc_subscribe_ctx *sc = NULL;
        STAILQ_FOREACH(sc, &ce->subscriptions, next) {
          if (sc->handle == p->handle) break;
        }
        if (sc == NULL) continue;
        sc->success = (p->status == ESP_GATT_OK);
        if (sc->success) {
          /* 4 descriptors should be enough for everyone. */
          esp_gattc_descr_elem_t cccd;
          uint16_t count = 1;
          esp_bt_uuid_t cccd_uuid = {
              .len = ESP_UUID_LEN_16,
              .uuid = {
                  .uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG, }};
          esp_gatt_status_t status = esp_ble_gattc_get_descr_by_char_handle(
              ce->bc.gatt_if, ce->bc.conn_id, sc->handle, cccd_uuid, &cccd,
              &count);
          sc->success = (status == ESP_GATT_OK);
          if (count == 1) {
            LOG(LL_DEBUG,
                ("%s %s -> CCCD handle %u",
                 mgos_bt_uuid_to_str(&sc->svc_uuid, buf),
                 mgos_bt_uuid_to_str(&sc->char_uuid, buf2), cccd.handle));
            uint8_t notify_en[2] = {0x01, 0x00};
            sc->cccd_handle = cccd.handle;
            status = esp_ble_gattc_write_char_descr(
                ce->bc.gatt_if, ce->bc.conn_id, sc->cccd_handle, 2, notify_en,
                ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
            sc->success = (status == ESP_GATT_OK);
            if (!sc->success) {
              LOG(LL_ERROR, ("esp_ble_gattc_write_char_descr(%u) = %d",
                             sc->cccd_handle, status));
            }
          } else {
            LOG(LL_ERROR,
                ("No CCCD for %s %s", mgos_bt_uuid_to_str(&sc->svc_uuid, buf),
                 mgos_bt_uuid_to_str(&sc->char_uuid, buf2)));
            sc->success = false;
          }
        }
        if (!sc->success) {
          STAILQ_REMOVE(&ce->subscriptions, sc, esp32_gattc_subscribe_ctx,
                        next);
          mgos_invoke_cb(subscribe_mgos_cb, sc, false /* from_isr */);
        } else {
          /* If everything is wfine, this means we sent out a CCCD write and
           * waiting for it to complete. */
        }
      }
      break;
    }
    case ESP_GATTC_UNREG_FOR_NOTIFY_EVT: {
      const struct gattc_unreg_for_notify_evt_param *p = &ep->unreg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("UNREG_FOR_NOTIFY st %d h %u", p->status, p->handle));
      break;
    }
    case ESP_GATTC_CONNECT_EVT: {
      const struct gattc_connect_evt_param *p = &ep->connect;
      LOG(LL_DEBUG, ("CONNECT cid %u addr %s", p->conn_id,
                     mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT: {
      const struct gattc_disconnect_evt_param *p = &ep->disconnect;
      LOG(LL_DEBUG, ("DISCONNECT cid %u addr %s", p->conn_id,
                     mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_READ_MUTIPLE_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("READ_MUTIPLE st %d cid %u h %u val_len %u", p->status,
               p->conn_id, p->handle, p->value_len));
      break;
    }
    case ESP_GATTC_QUEUE_FULL_EVT: {
      const struct gattc_queue_full_evt_param *p = &ep->queue_full;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("QUEUE_FULL st %d cid %u is_full %d", p->status, p->conn_id,
               p->is_full));
      break;
    }
  }
}

static void gattc_open_do_open(struct esp32_gattc_connection_entry *ce) {
  if (esp_ble_gattc_open(ce->bc.gatt_if, ce->bc.peer_addr,
                         true /* is_direct */) != ESP_OK) {
    open_done(ce, false);
    remove_connection(ce);
  }
}

static void gattc_open_addr_scan_cb(int num_res,
                                    const struct mgos_bt_ble_scan_result *res,
                                    void *arg) {
  char buf[BT_ADDR_STR_LEN];
  struct esp32_gattc_connection_entry *ce =
      (struct esp32_gattc_connection_entry *) arg;
  if (num_res <= 0) {
    LOG(LL_ERROR, ("%s not found (%d)",
                   mgos_bt_addr_to_str(ce->bc.peer_addr, buf), num_res));
    open_done(ce, false);
    remove_connection(ce);
    return;
  }
  LOG(LL_INFO, ("%s found, RSSI %d", mgos_bt_addr_to_str(ce->bc.peer_addr, buf),
                res->rssi));
  gattc_open_do_open(ce);
}

static void mgos_bt_gattc_open_addr_internal(const esp_bd_addr_t addr,
                                             bool need_scan,
                                             mgos_bt_gattc_open_cb cb,
                                             void *cb_arg) {
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
  ce->bc.mtu = ESP_GATT_DEF_BLE_MTU_SIZE;
  memcpy(ce->bc.peer_addr, addr, ESP_BD_ADDR_LEN);
  struct esp32_gattc_open_ctx *octx =
      (struct esp32_gattc_open_ctx *) calloc(1, sizeof(*ce->open_ctx));
  octx->conn_id = ce->conn_id;
  octx->cb = cb;
  octx->cb_arg = cb_arg;
  ce->open_ctx = octx;
  STAILQ_INIT(&ce->read_reqs);
  STAILQ_INIT(&ce->write_reqs);
  STAILQ_INIT(&ce->subscriptions);
  SLIST_INSERT_HEAD(&s_conns, ce, next);
  if (need_scan) {
    LOG(LL_INFO,
        ("Looking for %s", mgos_bt_addr_to_str(ce->bc.peer_addr, buf)));
    struct mgos_bt_ble_scan_opts opts = {0}; /* Use defaults */
    memcpy(opts.addr, ce->bc.peer_addr, sizeof(opts.addr));
    mgos_bt_ble_scan(&opts, gattc_open_addr_scan_cb, ce);
  } else {
    gattc_open_do_open(ce);
  }
}

void mgos_bt_gattc_open_addr(const esp_bd_addr_t addr, mgos_bt_gattc_open_cb cb,
                             void *cb_arg) {
  return mgos_bt_gattc_open_addr_internal(addr, false /* need_scan */, cb,
                                          cb_arg);
}

struct open_name_ctx {
  struct mg_str name;
  mgos_bt_gattc_open_cb cb;
  void *cb_arg;
};

static void gattc_open_name_scan_cb(int num_res,
                                    const struct mgos_bt_ble_scan_result *res,
                                    void *arg) {
  struct open_name_ctx *octx = (struct open_name_ctx *) arg;
  char buf[BT_ADDR_STR_LEN];
  if (num_res > 0) {
    LOG(LL_INFO,
        ("%.*s found, addr %s, RSSI %d", (int) octx->name.len, octx->name.p,
         mgos_bt_addr_to_str(res->addr, buf), res->rssi));
    mgos_bt_gattc_open_addr_internal(res->addr, false /* need_scan */, octx->cb,
                                     octx->cb_arg);
  } else {
    LOG(LL_ERROR,
        ("%.*s not found (%d)", (int) octx->name.len, octx->name.p, num_res));
    octx->cb(-1, false, octx->cb_arg);
  }
  free((void *) octx->name.p);
  free(octx);
}

void mgos_bt_gattc_open_name(const struct mg_str name, mgos_bt_gattc_open_cb cb,
                             void *cb_arg) {
  struct open_name_ctx *octx =
      (struct open_name_ctx *) calloc(1, sizeof(*octx));
  octx->name = mg_strdup(name);
  octx->cb = cb;
  octx->cb_arg = cb_arg;
  LOG(LL_INFO, ("Looking for %.*s", (int) name.len, name.p));
  struct mgos_bt_ble_scan_opts opts = {
      .name = name,
  };
  mgos_bt_ble_scan(&opts, gattc_open_name_scan_cb, octx);
}

bool mgos_bt_gattc_get_conn_info(int conn_id, struct esp32_bt_connection *bc) {
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) return false;
  memcpy(bc, &ce->bc, sizeof(*bc));
  return true;
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

struct esp32_gattc_list_chars_ctx {
  int conn_id;
  esp_bt_uuid_t svc_id;
  int num_res;
  struct mgos_bt_gattc_list_chars_result *res;
  mgos_bt_gattc_list_chars_cb_t cb;
  void *cb_arg;
};

static void lc_done_mgos_cb(void *arg) {
  struct esp32_gattc_list_chars_ctx *lc_ctx =
      (struct esp32_gattc_list_chars_ctx *) arg;
  lc_ctx->cb(lc_ctx->conn_id, &lc_ctx->svc_id, lc_ctx->num_res, lc_ctx->res,
             lc_ctx->cb_arg);
  free(lc_ctx->res);
  free(lc_ctx);
}

void mgos_bt_gattc_list_chars(int conn_id, const esp_bt_uuid_t *svc_id,
                              mgos_bt_gattc_list_chars_cb_t cb, void *cb_arg) {
  esp_gattc_char_elem_t *char_res = NULL;
  struct esp32_gattc_list_chars_ctx *lc_ctx = calloc(1, sizeof(*lc_ctx));
  if (lc_ctx == NULL) {
    cb(conn_id, svc_id, -2, NULL, cb_arg);
    return;
  }
  lc_ctx->conn_id = conn_id;
  memcpy(&lc_ctx->svc_id, svc_id, sizeof(lc_ctx->svc_id));
  lc_ctx->cb = cb;
  lc_ctx->cb_arg = cb_arg;
  struct esp32_gattc_connection_entry *ce = find_connection_by_id(conn_id);
  if (ce == NULL) {
    lc_ctx->num_res = -1;
    goto clean;
  }
  esp_gattc_service_elem_t svc_res;
  uint16_t count = 1;
  esp_gatt_status_t st = esp_ble_gattc_get_service(
      ce->bc.gatt_if, ce->bc.conn_id, &lc_ctx->svc_id, &svc_res, &count, 0);
  if (st != ESP_GATT_OK) {
    lc_ctx->num_res = -2;
    goto clean;
  }
  count = 0;
  st = esp_ble_gattc_get_attr_count(
      ce->bc.gatt_if, ce->bc.conn_id, ESP_GATT_DB_CHARACTERISTIC,
      svc_res.start_handle, svc_res.end_handle, 0, &count);
  if (st != ESP_GATT_OK) {
    lc_ctx->num_res = -3;
    goto clean;
  }
  char_res = (esp_gattc_char_elem_t *) calloc(count, sizeof(*char_res));
  if (char_res == NULL) {
    lc_ctx->num_res = -4;
    goto clean;
  }
  st = esp_ble_gattc_get_all_char(ce->bc.gatt_if, ce->bc.conn_id,
                                  svc_res.start_handle, svc_res.end_handle,
                                  char_res, &count, 0);
  if (st != ESP_GATT_OK) {
    lc_ctx->num_res = -5;
    goto clean;
  }
  lc_ctx->res = (struct mgos_bt_gattc_list_chars_result *) calloc(
      count, sizeof(*lc_ctx->res));
  if (lc_ctx->res == NULL) {
    lc_ctx->num_res = -6;
    goto clean;
  }
  lc_ctx->num_res = count;
  for (uint16_t i = 0; i < count; i++) {
    esp_gattc_char_elem_t *el = &char_res[i];
    struct mgos_bt_gattc_list_chars_result *res = &lc_ctx->res[i];
    memcpy(&res->char_id, &el->uuid, sizeof(res->char_id));
    res->char_prop = el->properties;
  }

clean:
  free(char_res);
  mgos_invoke_cb(lc_done_mgos_cb, lc_ctx, false /* from_isr */);
}

static esp_gatt_status_t esp32_gattc_get_char_handle(
    int conn_id, const esp_bt_uuid_t *svc_id, const esp_bt_uuid_t *char_id,
    struct esp32_gattc_connection_entry **ce, uint16_t *handle) {
  esp_gatt_status_t res = ESP_GATT_OK;
  esp_gattc_service_elem_t svc_res;
  esp_gattc_char_elem_t char_res;
  uint16_t count = 1;
  *handle = 0;
  *ce = find_connection_by_id(conn_id);
  if (*ce == NULL) return ESP_GATT_INVALID_HANDLE;
  res =
      esp_ble_gattc_get_service((*ce)->bc.gatt_if, (*ce)->bc.conn_id,
                                (esp_bt_uuid_t *) svc_id, &svc_res, &count, 0);
  if (res != ESP_GATT_OK) goto clean;
  count = 1;
  res = esp_ble_gattc_get_char_by_uuid((*ce)->bc.gatt_if, (*ce)->bc.conn_id,
                                       svc_res.start_handle, svc_res.end_handle,
                                       *char_id, &char_res, &count);
  if (res != ESP_GATT_OK) goto clean;
  *handle = char_res.char_handle;

clean : {
  enum cs_log_level ll = (res == ESP_GATT_OK ? LL_DEBUG : LL_ERROR);
  char buf1[BT_UUID_STR_LEN], buf2[BT_UUID_STR_LEN];
  LOG(ll, ("%s %s -> %u", mgos_bt_uuid_to_str(svc_id, buf1),
           mgos_bt_uuid_to_str(char_id, buf2), *handle));
}
  return res;
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

void mgos_bt_gattc_read_char(int conn_id, const esp_bt_uuid_t *svc_uuid,
                             const esp_bt_uuid_t *char_uuid,
                             esp_gatt_auth_req_t auth_req,
                             mgos_bt_gattc_read_char_cb_t cb, void *cb_arg) {
  struct esp32_gattc_read_char_ctx *rc = calloc(1, sizeof(*rc));
  if (rc == NULL) {
    cb(conn_id, false, mg_mk_str(NULL), cb_arg);
    return;
  }
  rc->conn_id = conn_id;
  memcpy(&rc->svc_uuid, svc_uuid, sizeof(rc->svc_uuid));
  memcpy(&rc->char_uuid, char_uuid, sizeof(rc->char_uuid));
  rc->cb = cb;
  rc->cb_arg = cb_arg;
  struct esp32_gattc_connection_entry *ce = NULL;
  esp_gatt_status_t st = esp32_gattc_get_char_handle(
      conn_id, svc_uuid, char_uuid, &ce, &rc->handle);
  if (st != ESP_GATT_OK) {
    rc->value_len = -1;
    goto clean;
  }
  STAILQ_INSERT_TAIL(&ce->read_reqs, rc, next);
  if (esp_ble_gattc_read_char(ce->bc.gatt_if, ce->bc.conn_id, rc->handle,
                              auth_req) != ESP_GATT_OK) {
    STAILQ_REMOVE(&ce->read_reqs, rc, esp32_gattc_read_char_ctx, next);
    rc->value_len = -2;
    goto clean;
  }

clean:
  if (rc->value_len < 0) {
    mgos_invoke_cb(read_done_mgos_cb, rc, false /* from_isr */);
  }
}

static void write_done_mgos_cb(void *arg) {
  struct esp32_gattc_write_char_ctx *wc =
      (struct esp32_gattc_write_char_ctx *) arg;
  wc->cb(wc->conn_id, wc->success, wc->cb_arg);
  free(wc);
}

void mgos_bt_gattc_write_char(int conn_id, const esp_bt_uuid_t *svc_uuid,
                              const esp_bt_uuid_t *char_uuid,
                              bool response_required,
                              esp_gatt_auth_req_t auth_req,
                              const struct mg_str value,
                              mgos_bt_gattc_write_char_cb_t cb, void *cb_arg) {
  struct esp32_gattc_write_char_ctx *wc = calloc(1, sizeof(*wc));
  if (wc == NULL) {
    cb(conn_id, false, cb_arg);
    return;
  }
  wc->conn_id = conn_id;
  memcpy(&wc->svc_uuid, svc_uuid, sizeof(wc->svc_uuid));
  memcpy(&wc->char_uuid, char_uuid, sizeof(wc->char_uuid));
  wc->cb = cb;
  wc->cb_arg = cb_arg;
  struct esp32_gattc_connection_entry *ce;
  esp_gatt_status_t st = esp32_gattc_get_char_handle(
      conn_id, svc_uuid, char_uuid, &ce, &wc->handle);
  if (st != ESP_GATT_OK) {
    wc->success = false;
    goto clean;
  }
  STAILQ_INSERT_TAIL(&ce->write_reqs, wc, next);
  wc->success = true;
  if (esp_ble_gattc_write_char(ce->bc.gatt_if, ce->bc.conn_id, wc->handle,
                               value.len, (uint8_t *) value.p,
                               (response_required ? ESP_GATT_WRITE_TYPE_RSP
                                                  : ESP_GATT_WRITE_TYPE_NO_RSP),
                               auth_req) != ESP_OK) {
    STAILQ_REMOVE(&ce->write_reqs, wc, esp32_gattc_write_char_ctx, next);
    wc->success = false;
    goto clean;
  }

clean:
  if (!wc->success) {
    mgos_invoke_cb(write_done_mgos_cb, wc, false /* from_isr */);
  }
}

static void subscribe_mgos_cb(void *arg) {
  struct esp32_gattc_subscribe_ctx *sc =
      (struct esp32_gattc_subscribe_ctx *) arg;
  /* FIXME(rojer): Locking */
  uint8_t *values = sc->values;
  uint16_t values_len = sc->values_len;
  sc->values = NULL;
  sc->values_len = 0;
  struct mg_str value = MG_NULL_STR;
  if (sc->success && values != NULL) {
    for (uint16_t i = 0; i < values_len;) {
      value.len = ((uint16_t) values[i] | (((uint16_t) values[i + 1]) << 8));
      value.p = (const char *) (values + i + 2);
      i += 2 + value.len;
      sc->cb(sc->conn_id, sc->success, value, sc->cb_arg);
    }
  } else {
    sc->cb(sc->conn_id, sc->success, value, sc->cb_arg);
  }
  if (values != NULL) free(values);
  if (!sc->success) free(sc);
}

void mgos_bt_gattc_subscribe(int conn_id, const esp_bt_uuid_t *svc_uuid,
                             const esp_bt_uuid_t *char_uuid,
                             mgos_bt_gattc_subscribe_cb_t cb, void *cb_arg) {
  struct esp32_gattc_subscribe_ctx *sc = calloc(1, sizeof(*sc));
  if (sc == NULL) {
    cb(conn_id, false, mg_mk_str_n(NULL, 0), cb_arg);
    return;
  }
  sc->conn_id = conn_id;
  memcpy(&sc->svc_uuid, svc_uuid, sizeof(sc->svc_uuid));
  memcpy(&sc->char_uuid, char_uuid, sizeof(sc->char_uuid));
  sc->cb = cb;
  sc->cb_arg = cb_arg;
  struct esp32_gattc_connection_entry *ce;
  esp_gatt_status_t st = esp32_gattc_get_char_handle(
      conn_id, svc_uuid, char_uuid, &ce, &sc->handle);
  if (st != ESP_GATT_OK) {
    sc->success = false;
    goto clean;
  }
  STAILQ_INSERT_TAIL(&ce->subscriptions, sc, next);
  sc->success = true;
  if (esp_ble_gattc_register_for_notify(ce->bc.gatt_if, ce->bc.peer_addr,
                                        sc->handle) != ESP_OK) {
    STAILQ_REMOVE(&ce->subscriptions, sc, esp32_gattc_subscribe_ctx, next);
    sc->success = false;
    goto clean;
  }
  return;

clean:
  mgos_invoke_cb(subscribe_mgos_cb, sc, false /* from_isr */);
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
