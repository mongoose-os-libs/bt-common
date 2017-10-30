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
#include "esp_gatt_common_api.h"
#include "esp_gatts_api.h"

#include "common/cs_dbg.h"
#include "common/queue.h"

#include "mgos_hal.h"
#include "mgos_sys_config.h"

struct esp32_bt_service_entry {
  const esp_gatts_attr_db_t *svc_descr;
  size_t num_attrs;
  bool registered;
  mgos_bt_gatts_handler_t cb;
  void *cb_arg;
  uint16_t *attr_handles;
  SLIST_ENTRY(esp32_bt_service_entry) next;
};

struct esp32_gatts_session_entry {
  struct esp32_bt_session bs;
  struct esp32_bt_service_entry *se;
  SLIST_ENTRY(esp32_gatts_session_entry) next;
};

struct esp32_gatts_connection_entry {
  struct esp32_bt_connection bc;
  SLIST_HEAD(sessions, esp32_gatts_session_entry) sessions;
  SLIST_ENTRY(esp32_gatts_connection_entry) next;
};

struct esp32_gatts_ev_info {
  struct esp32_bt_service_entry *se;
  struct esp32_gatts_session_entry *sse;
  esp_gatts_cb_event_t ev;
  esp_ble_gatts_cb_param_t ep;
};

static SLIST_HEAD(s_svcs, esp32_bt_service_entry) s_svcs =
    SLIST_HEAD_INITIALIZER(s_svcs);
static SLIST_HEAD(s_conns, esp32_gatts_connection_entry) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static const char *s_dev_name = NULL;
static bool s_gatts_registered = false;
static esp_gatt_if_t s_gatts_if;

const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
const uint16_t char_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
const uint8_t char_prop_read_write =
    (ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE);
const uint8_t char_prop_read_notify =
    (ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY);
const uint8_t char_prop_write = (ESP_GATT_CHAR_PROP_BIT_WRITE);

static esp_ble_adv_data_t mos_rpc_adv_data = {
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

static void esp32_bt_register_services(void) {
  struct esp32_bt_service_entry *se;
  if (!s_gatts_registered) return;
  SLIST_FOREACH(se, &s_svcs, next) {
    if (se->registered) continue;
    esp_err_t r = esp_ble_gatts_create_attr_tab(se->svc_descr, s_gatts_if,
                                                se->num_attrs, 0);
    LOG(LL_DEBUG, ("esp_ble_gatts_create_attr_tab %d", r));
    se->registered = true;
  }
}

static struct esp32_bt_service_entry *find_service_by_uuid(
    const esp_bt_uuid_t *uuid) {
  struct esp32_bt_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    if (se->svc_descr[0].att_desc.length == uuid->len &&
        memcmp(se->svc_descr[0].att_desc.value, uuid->uuid.uuid128,
               uuid->len) == 0) {
      return se;
    }
  }
  return NULL;
}

static struct esp32_bt_service_entry *find_service_by_attr_handle(
    uint16_t attr_handle) {
  struct esp32_bt_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    for (size_t i = 0; i < se->num_attrs; i++) {
      if (se->attr_handles[i] == attr_handle) return se;
    }
  }
  return NULL;
}

static struct esp32_gatts_connection_entry *find_connection(
    esp_gatt_if_t gatt_if, uint16_t conn_id) {
  struct esp32_gatts_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->bc.gatt_if == gatt_if && ce->bc.conn_id == conn_id) return ce;
  }
  return NULL;
}

/* Executed on the main task. */
static void gatts_ev_mgos(void *arg) {
  struct esp32_gatts_ev_info *ei = (struct esp32_gatts_ev_info *) arg;
  struct esp32_bt_session *bs = (ei->sse != NULL ? &ei->sse->bs : NULL);
  bool ret = ei->se->cb(bs, ei->ev, &ei->ep);
  switch (ei->ev) {
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      free(ei->ep.add_attr_tab.handles);
      break;
    }
    case ESP_GATTS_READ_EVT: {
      if (!ret) {
        esp_ble_gatts_send_response(
            ei->sse->bs.bc->gatt_if, ei->sse->bs.bc->conn_id,
            ei->ep.read.trans_id, ESP_GATT_READ_NOT_PERMIT, NULL);
      } else {
        /* Response was sent by the callback. */
      }
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      if (ei->ep.write.need_rsp) {
        esp_ble_gatts_send_response(
            ei->sse->bs.bc->gatt_if, ei->sse->bs.bc->conn_id,
            ei->ep.write.trans_id,
            (ret ? ESP_GATT_OK : ESP_GATT_WRITE_NOT_PERMIT), NULL);
      }
      free(ei->ep.write.value);
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      free(ei->sse);
      break;
    }
    default:
      break;
  }
  free(ei);
};

static void run_on_mgos_task(struct esp32_gatts_session_entry *sse,
                             struct esp32_bt_service_entry *se,
                             esp_gatts_cb_event_t ev,
                             esp_ble_gatts_cb_param_t *ep) {
  struct esp32_gatts_ev_info *ei =
      (struct esp32_gatts_ev_info *) calloc(1, sizeof(*ei));
  ei->sse = sse;
  ei->se = se;
  ei->ev = ev;
  memcpy(&ei->ep, ep, sizeof(ei->ep));
  switch (ei->ev) {
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      /* Make a copy of handles */
      size_t len =
          ep->add_attr_tab.num_handle * sizeof(*ep->add_attr_tab.handles);
      uint16_t *handles_copy = (uint16_t *) malloc(len);
      memcpy(handles_copy, ep->add_attr_tab.handles, len);
      ei->ep.add_attr_tab.handles = handles_copy;
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      /* Make a copy of the value */
      uint8_t *value_copy = (uint8_t *) malloc(ep->write.len);
      memcpy(value_copy, ep->write.value, ep->write.len);
      ei->ep.write.value = value_copy;
      break;
    }
    default:
      break;
  }
  mgos_invoke_cb(gatts_ev_mgos, ei, false /* from_isr */);
}

static void esp32_bt_gatts_ev(esp_gatts_cb_event_t ev, esp_gatt_if_t gatts_if,
                              esp_ble_gatts_cb_param_t *ep) {
  esp_err_t r;
  char buf[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GATTS_REG_EVT: {
      const struct gatts_reg_evt_param *p = &ep->reg;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG if %d st %d app %d", gatts_if, p->status, p->app_id));
      if (p->status != ESP_GATT_OK) break;
      esp_ble_gap_set_device_name(s_dev_name);
      r = esp_ble_gap_config_adv_data(&mos_rpc_adv_data);
      LOG(LL_DEBUG, ("esp_ble_gap_config_adv_data %d", r));
      s_gatts_if = gatts_if;
      s_gatts_registered = true;
      esp32_bt_register_services();
      break;
    }
    case ESP_GATTS_READ_EVT: {
      const struct gatts_read_evt_param *p = &ep->read;
      LOG(LL_DEBUG, ("READ %s cid %d tid 0x%08x h %u off %d%s%s",
                     mgos_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, (p->is_long ? " long" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      if (!p->need_rsp) break;
      struct esp32_gatts_connection_entry *ce =
          find_connection(gatts_if, p->conn_id);
      if (ce != NULL) {
        struct esp32_bt_service_entry *se =
            find_service_by_attr_handle(p->handle);
        struct esp32_gatts_session_entry *sse;
        SLIST_FOREACH(sse, &ce->sessions, next) {
          if (sse->se == se) {
            run_on_mgos_task(sse, sse->se, ev, ep);
          }
        }
      }
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ep->write;
      LOG(LL_DEBUG, ("WRITE %s cid %d tid 0x%08x h %u off %d len %d%s%s",
                     mgos_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, p->len, (p->is_prep ? " prep" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      if (!p->need_rsp) break;
      struct esp32_gatts_connection_entry *ce =
          find_connection(gatts_if, p->conn_id);
      if (ce != NULL) {
        struct esp32_bt_service_entry *se =
            find_service_by_attr_handle(p->handle);
        struct esp32_gatts_session_entry *sse;
        SLIST_FOREACH(sse, &ce->sessions, next) {
          if (sse->se == se) {
            run_on_mgos_task(sse, sse->se, ev, ep);
          }
        }
      }
      break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT: {
      const struct gatts_exec_write_evt_param *p = &ep->exec_write;
      LOG(LL_DEBUG, ("EXEC_WRITE %s cid %d tid 0x%08x flag %d",
                     mgos_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->exec_write_flag));
      break;
    }
    case ESP_GATTS_MTU_EVT: {
      const struct gatts_mtu_evt_param *p = &ep->mtu;
      LOG(LL_DEBUG, ("MTU cid %d mtu %d", p->conn_id, p->mtu));
      struct esp32_gatts_connection_entry *ce =
          find_connection(gatts_if, p->conn_id);
      if (ce != NULL) ce->bc.mtu = p->mtu;
      break;
    }
    case ESP_GATTS_CONF_EVT: {
      const struct gatts_conf_evt_param *p = &ep->conf;
      LOG(LL_DEBUG, ("CONF cid %d st %d", p->conn_id, p->status));
      break;
    }
    case ESP_GATTS_UNREG_EVT: {
      LOG(LL_DEBUG, ("UNREG"));
      break;
    }
    case ESP_GATTS_CREATE_EVT: {
      const struct gatts_create_evt_param *p = &ep->create;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("CREATE st %d svch %d svcid %s %d%s", p->status, p->service_handle,
           mgos_bt_uuid_to_str(&p->service_id.id.uuid, buf),
           p->service_id.id.inst_id,
           (p->service_id.is_primary ? " primary" : "")));
      break;
    }
    case ESP_GATTS_ADD_INCL_SRVC_EVT: {
      const struct gatts_add_incl_srvc_evt_param *p = &ep->add_incl_srvc;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("ADD_INCL_SRVC st %d ah %u svch %u", p->status, p->attr_handle,
               p->service_handle));
      break;
    }
    case ESP_GATTS_ADD_CHAR_EVT: {
      const struct gatts_add_char_evt_param *p = &ep->add_char;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("ADD_CHAR st %d ah %u svch %u uuid %s", p->status, p->attr_handle,
           p->service_handle, mgos_bt_uuid_to_str(&p->char_uuid, buf)));
      break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT: {
      const struct gatts_add_char_descr_evt_param *p = &ep->add_char_descr;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("ADD_CHAR_DESCR st %d ah %u svch %u uuid %s", p->status,
               p->attr_handle, p->service_handle,
               mgos_bt_uuid_to_str(&p->char_uuid, buf)));
      break;
    }
    case ESP_GATTS_DELETE_EVT: {
      const struct gatts_delete_evt_param *p = &ep->del;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("DELETE st %d svch %u", p->status, p->service_handle));
      break;
    }
    case ESP_GATTS_START_EVT: {
      const struct gatts_start_evt_param *p = &ep->start;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("START st %d svch %u", p->status, p->service_handle));
      break;
    }
    case ESP_GATTS_STOP_EVT: {
      const struct gatts_stop_evt_param *p = &ep->stop;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("STOP st %d svch %u", p->status, p->service_handle));
      break;
    }
    case ESP_GATTS_CONNECT_EVT: {
      const struct gatts_connect_evt_param *p = &ep->connect;
      LOG(LL_INFO, ("CONNECT cid %d addr %s%s", p->conn_id,
                    mgos_bt_addr_to_str(p->remote_bda, buf),
                    (p->is_connected ? " connected" : "")));
      if (!p->is_connected) break;
      esp_ble_conn_update_params_t conn_params = {0};
      memcpy(conn_params.bda, p->remote_bda, ESP_BD_ADDR_LEN);
      conn_params.latency = 0;
      conn_params.max_int = 0x50; /* max_int = 0x50*1.25ms = 100ms */
      conn_params.min_int = 0x30; /* min_int = 0x30*1.25ms = 60ms */
      conn_params.timeout = 400;  /* timeout = 400*10ms = 4000ms */
      esp_ble_gap_update_conn_params(&conn_params);
      /* Resume advertising */
      if (mgos_sys_config_get_bt_adv_enable() && !is_scanning()) {
        start_advertising();
      }
      struct esp32_gatts_connection_entry *ce =
          (struct esp32_gatts_connection_entry *) calloc(1, sizeof(*ce));
      ce->bc.gatt_if = gatts_if;
      ce->bc.conn_id = p->conn_id;
      ce->bc.mtu = ESP_GATT_DEF_BLE_MTU_SIZE;
      memcpy(ce->bc.peer_addr, p->remote_bda, ESP_BD_ADDR_LEN);
      /* Create a session for each of the currently registered services. */
      struct esp32_bt_service_entry *se;
      SLIST_FOREACH(se, &s_svcs, next) {
        struct esp32_gatts_session_entry *sse =
            (struct esp32_gatts_session_entry *) calloc(1, sizeof(*sse));
        sse->se = se;
        sse->bs.bc = &ce->bc;
        SLIST_INSERT_HEAD(&ce->sessions, sse, next);
        run_on_mgos_task(sse, sse->se, ev, ep);
      }
      SLIST_INSERT_HEAD(&s_conns, ce, next);
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      const struct gatts_disconnect_evt_param *p = &ep->disconnect;
      LOG(LL_INFO, ("DISCONNECT cid %d addr %s%s", p->conn_id,
                    mgos_bt_addr_to_str(p->remote_bda, buf),
                    (p->is_connected ? " connected" : "")));

      struct esp32_gatts_connection_entry *ce =
          find_connection(gatts_if, p->conn_id);
      if (ce != NULL) {
        struct esp32_gatts_session_entry *sse, *sset;
        SLIST_FOREACH_SAFE(sse, &ce->sessions, next, sset) {
          run_on_mgos_task(sse, sse->se, ev, ep);
        }
        SLIST_REMOVE(&s_conns, ce, esp32_gatts_connection_entry, next);
        free(ce);
      }
      if (mgos_sys_config_get_bt_adv_enable() && !is_scanning()) {
        start_advertising();
      }
      break;
    }
    case ESP_GATTS_OPEN_EVT: {
      const struct gatts_open_evt_param *p = &ep->open;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("OPEN st %d", p->status));
      break;
    }
    case ESP_GATTS_CANCEL_OPEN_EVT: {
      const struct gatts_cancel_open_evt_param *p = &ep->cancel_open;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CANCEL_OPEN st %d", p->status));
      break;
    }
    case ESP_GATTS_CLOSE_EVT: {
      const struct gatts_close_evt_param *p = &ep->close;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CLOSE st %d cid %d", p->status, p->conn_id));
      break;
    }
    case ESP_GATTS_LISTEN_EVT: {
      LOG(LL_DEBUG, ("LISTEN"));
      break;
    }
    case ESP_GATTS_CONGEST_EVT: {
      const struct gatts_congest_evt_param *p = &ep->congest;
      LOG(LL_DEBUG,
          ("CONGEST cid %d%s", p->conn_id, (p->congested ? " congested" : "")));
      break;
    }
    case ESP_GATTS_RESPONSE_EVT: {
      const struct gatts_rsp_evt_param *p = &ep->rsp;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("RESPONSE st %d ah %d", p->status, p->handle));
      break;
    }
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      const struct gatts_add_attr_tab_evt_param *p = &ep->add_attr_tab;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("CREAT_ATTR_TAB st %d svc_uuid %s nh %d hh %p", p->status,
           mgos_bt_uuid_to_str(&p->svc_uuid, buf), p->num_handle, p->handles));
      if (p->status != 0) {
        LOG(LL_ERROR,
            ("Failed to register service attribute table: %d", p->status));
        break;
      }
      struct esp32_bt_service_entry *se = find_service_by_uuid(&p->svc_uuid);
      if (se == NULL || se->num_attrs != p->num_handle) break;
      se->attr_handles =
          (uint16_t *) calloc(p->num_handle, sizeof(*se->attr_handles));
      memcpy(se->attr_handles, p->handles,
             p->num_handle * sizeof(*se->attr_handles));
      run_on_mgos_task(NULL, se, ev, ep);
      uint16_t svch = se->attr_handles[0];
      LOG(LL_INFO,
          ("Starting BT service %s", mgos_bt_uuid_to_str(&p->svc_uuid, buf)));
      esp_ble_gatts_start_service(svch);
      break;
    }
    case ESP_GATTS_SET_ATTR_VAL_EVT: {
      const struct gatts_set_attr_val_evt_param *p = &ep->set_attr_val;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SET_ATTR_VAL sh %d ah %d st %d", p->srvc_handle, p->attr_handle,
               p->status));
      break;
    }
  }
}

bool mgos_bt_gatts_register_service(const esp_gatts_attr_db_t *svc_descr,
                                    size_t num_attrs,
                                    mgos_bt_gatts_handler_t cb) {
  if (cb == NULL) return false;
  struct esp32_bt_service_entry *se =
      (struct esp32_bt_service_entry *) calloc(1, sizeof(*se));
  if (se == NULL) return false;
  se->svc_descr = svc_descr;
  se->num_attrs = num_attrs;
  se->cb = cb;
  SLIST_INSERT_HEAD(&s_svcs, se, next);
  esp32_bt_register_services();
  return true;
}

bool esp32_bt_gatts_init(void) {
  s_dev_name = mgos_sys_config_get_bt_dev_name();
  if (s_dev_name == NULL) s_dev_name = mgos_sys_config_get_device_id();
  if (s_dev_name == NULL) {
    LOG(LL_ERROR, ("bt.dev_name or device.id must be set"));
    return false;
  }
  LOG(LL_INFO, ("BT device name %s", s_dev_name));
  return (esp_ble_gatts_register_callback(esp32_bt_gatts_ev) == ESP_OK &&
          esp_ble_gatts_app_register(0) == ESP_OK);
}
