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

#include "esp32_bt_gatts.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_bt.h"
#include "esp_bt_defs.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_common_api.h"
#include "esp_gatts_api.h"

#include "common/cs_dbg.h"
#include "common/mbuf.h"
#include "common/queue.h"

#include "mgos_hal.h"
#include "mgos_sys_config.h"

#include "esp32_bt_internal.h"

#ifndef MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN
#define MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN 4096
#endif

struct esp32_bt_service_entry {
  const esp_gatts_attr_db_t *svc_descr;
  size_t num_attrs;
  bool registered;
  mgos_bt_gatts_handler_t cb;
  void *cb_arg;
  uint16_t *attr_handles;
  SLIST_ENTRY(esp32_bt_service_entry) next;
};

struct esp32_bt_gatts_pending_write {
  uint16_t handle;
  struct mbuf value;
  SLIST_ENTRY(esp32_bt_gatts_pending_write) next;
};

struct esp32_gatts_session_entry {
  struct esp32_bt_session bs;
  struct esp32_bt_service_entry *se;
  SLIST_HEAD(pending_writes, esp32_bt_gatts_pending_write) pending_writes;
  SLIST_ENTRY(esp32_gatts_session_entry) next;
};

struct esp32_gatts_connection_entry {
  struct esp32_bt_connection bc;
  bool need_auth;
  SLIST_HEAD(sessions, esp32_gatts_session_entry) sessions;
  SLIST_ENTRY(esp32_gatts_connection_entry) next;
};

struct ind_pending {
  esp_gatt_if_t gatts_if;
  uint16_t conn_id;
  uint16_t handle;
  struct mg_str value;
  bool need_confirm;
  STAILQ_ENTRY(ind_pending) next;
};

struct esp32_gatts_ev_info {
  esp_gatt_if_t gatts_if;
  struct esp32_bt_service_entry *se;
  struct esp32_gatts_session_entry *sse;
  esp_gatts_cb_event_t ev;
  esp_ble_gatts_cb_param_t ep;
};

static SLIST_HEAD(s_svcs, esp32_bt_service_entry) s_svcs =
    SLIST_HEAD_INITIALIZER(s_svcs);
static SLIST_HEAD(s_conns, esp32_gatts_connection_entry) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static STAILQ_HEAD(s_inds_pending, ind_pending)
    s_inds_pending = STAILQ_HEAD_INITIALIZER(s_inds_pending);

static bool s_gatts_registered = false;
static esp_gatt_if_t s_gatts_if;

const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
const uint16_t char_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
const uint16_t char_client_config_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
const uint8_t char_prop_read = ESP_GATT_CHAR_PROP_BIT_READ;
const uint8_t char_prop_read_write =
    (ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE);
const uint8_t char_prop_read_notify =
    (ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY);
const uint8_t char_prop_read_write_notify =
    (ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE |
     ESP_GATT_CHAR_PROP_BIT_NOTIFY);
const uint8_t char_prop_write = (ESP_GATT_CHAR_PROP_BIT_WRITE);

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

static struct esp32_gatts_session_entry *find_session(esp_gatt_if_t gatt_if,
                                                      uint16_t conn_id,
                                                      uint16_t handle) {
  struct esp32_gatts_connection_entry *ce = find_connection(gatt_if, conn_id);
  if (ce == NULL) return NULL;
  struct esp32_bt_service_entry *se = find_service_by_attr_handle(handle);
  if (se == NULL) return NULL;
  struct esp32_gatts_session_entry *sse;
  SLIST_FOREACH(sse, &ce->sessions, next) {
    if (sse->se == se) return sse;
  }
  return NULL;
}

/* Executed on the main task. */
static void gatts_ev_mgos(void *arg) {
  char buf[BT_UUID_STR_LEN];
  struct esp32_gatts_ev_info *ei = (struct esp32_gatts_ev_info *) arg;
  struct esp32_bt_session *bs = (ei->sse != NULL ? &ei->sse->bs : NULL);
  bool ret = (ei->se != NULL ? ei->se->cb(bs, ei->ev, &ei->ep) : false);
  switch (ei->ev) {
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      free(ei->ep.add_attr_tab.handles);
      break;
    }
    case ESP_GATTS_READ_EVT: {
      if (ei->ep.read.need_rsp && !ret) {
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
    case ESP_GATTS_EXEC_WRITE_EVT: {
      const struct gatts_exec_write_evt_param *p = &ei->ep.exec_write;
      struct esp32_gatts_connection_entry *ce =
          find_connection(ei->gatts_if, p->conn_id);
      if (ce == NULL) break;
      esp_gatt_status_t status = ESP_GATT_OK;
      struct esp32_gatts_session_entry *sse;
      SLIST_FOREACH(sse, &ce->sessions, next) {
        struct esp32_bt_gatts_pending_write *pw, *pwt;
        SLIST_FOREACH_SAFE(pw, &sse->pending_writes, next, pwt) {
          if (p->exec_write_flag == ESP_GATT_PREP_WRITE_EXEC) {
            /* Create a write event */
            esp_ble_gatts_cb_param_t ep = {
                .write =
                    {
                     .conn_id = p->conn_id,
                     .trans_id = p->trans_id,
                     .handle = pw->handle,
                     .offset = 0,
                     .need_rsp = true,
                     .is_prep = false,
                     .len = pw->value.len,
                     .value = (uint8_t *) pw->value.buf,
                    },
            };
            memcpy(ep.write.bda, p->bda, sizeof(ep.write.bda));
            const struct gatts_write_evt_param *wp = &ep.write;
            LOG(LL_DEBUG,
                ("WRITE (prepared) %s cid %d tid 0x%08x h %u off %d len %d%s%s",
                 esp32_bt_addr_to_str(wp->bda, buf), wp->conn_id, wp->trans_id,
                 wp->handle, wp->offset, wp->len, (wp->is_prep ? " prep" : ""),
                 (wp->need_rsp ? " need_rsp" : "")));
            if (!sse->se->cb(&sse->bs, ESP_GATTS_WRITE_EVT, &ep)) {
              status = ESP_GATT_WRITE_NOT_PERMIT;
            }
          } else {
            /* Must be cancel - do nothing, simply discard the write. */
          }
          mbuf_free(&pw->value);
          memset(pw, 0, sizeof(*pw));
          free(pw);
        }
        SLIST_INIT(&sse->pending_writes);
      }
      esp_ble_gatts_send_response(ei->gatts_if, ei->ep.exec_write.conn_id,
                                  ei->ep.exec_write.trans_id, status, NULL);
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      free(ei->sse);
      break;
    }
    case ESP_GATTS_CONF_EVT: {
      /*
       * Get the first item from the queue, it corresponds to the current CONF
       * event.
       */
      struct ind_pending *indp = STAILQ_FIRST(&s_inds_pending);
      if (indp == NULL) {
        /*
         * Unsolicited CONF event; one reason to get it is to use
         * esp_ble_gatts_send_indicate() instead of
         * mgos_bt_gatts_send_indicate(), but there are other weird cases;
         * e.g. see this:
         * https://github.com/cesanta/dev/blob/aa17ba60f16119f8b10658304ee6e612ba223d75/mos_libs/uart-bridge/src/bt_svc/bt_svc_esp32.c#L185
         */
        break;
      }
      STAILQ_REMOVE_HEAD(&s_inds_pending, next);

      /*
       * Call user's callback (since SDK doesn't provide `handle` for the CONF
       * event, it's called with `ei->sse` set to NULL, and thus we couldn't
       * call user's callback above for that event)
       */
      struct esp32_gatts_session_entry *sse =
          find_session(indp->gatts_if, indp->conn_id, indp->handle);
      if (sse != NULL) {
        sse->se->cb(&sse->bs, ei->ev, &ei->ep);
      } else {
        LOG(LL_ERROR, ("CONF on unknown conn_id %d and handle %d",
                       indp->conn_id, indp->handle));
      }

      free((char *) indp->value.p);
      free(indp);

      /* If there are some pending request(s), fire the next one */
      if (!STAILQ_EMPTY(&s_inds_pending)) {
        indp = STAILQ_FIRST(&s_inds_pending);
        esp_ble_gatts_send_indicate(indp->gatts_if, indp->conn_id, indp->handle,
                                    indp->value.len, (uint8_t *) indp->value.p,
                                    indp->need_confirm);
        /*
         * TODO(dfrank) if esp_ble_gatts_send_indicate has returned non-ok,
         * ideally we should emulate CONF event fully, with calling user
         * callback, etc
         */
      }
      break;
    }
    default:
      break;
  }
  memset(ei, 0, sizeof(*ei));
  free(ei);
};

static void run_on_mgos_task(esp_gatt_if_t gatts_if,
                             struct esp32_gatts_session_entry *sse,
                             struct esp32_bt_service_entry *se,
                             esp_gatts_cb_event_t ev,
                             esp_ble_gatts_cb_param_t *ep) {
  struct esp32_gatts_ev_info *ei =
      (struct esp32_gatts_ev_info *) calloc(1, sizeof(*ei));
  ei->gatts_if = gatts_if;
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

static bool is_paired(const esp_bd_addr_t addr) {
  bool result = false;
  int num = esp_ble_get_bond_device_num();
  esp_ble_bond_dev_t *list = (esp_ble_bond_dev_t *) calloc(num, sizeof(*list));
  if (list != NULL && esp_ble_get_bond_device_list(&num, list) == ESP_OK) {
    for (int i = 0; i < num; i++) {
      if (esp32_bt_addr_cmp(addr, list[i].bd_addr) == 0) {
        result = true;
        break;
      }
    }
  }
  free(list);
  return result;
}

static void create_sessions(struct esp32_gatts_connection_entry *ce) {
  /* Create a session for each of the currently registered services. */
  struct esp32_bt_service_entry *se;
  esp_ble_gatts_cb_param_t ep;
  ep.connect.conn_id = ce->bc.conn_id;
  memcpy(ep.connect.remote_bda, ce->bc.peer_addr.addr, ESP_BD_ADDR_LEN);
  SLIST_FOREACH(se, &s_svcs, next) {
    struct esp32_gatts_session_entry *sse =
        (struct esp32_gatts_session_entry *) calloc(1, sizeof(*sse));
    sse->se = se;
    sse->bs.bc = &ce->bc;
    SLIST_INSERT_HEAD(&ce->sessions, sse, next);
    run_on_mgos_task(ce->bc.gatt_if, sse, sse->se, ESP_GATTS_CONNECT_EVT, &ep);
  }
  esp_ble_conn_update_params_t conn_params = {0};
  memcpy(conn_params.bda, ce->bc.peer_addr.addr, ESP_BD_ADDR_LEN);
  conn_params.latency = 0;
  conn_params.max_int = 0x50; /* max_int = 0x50*1.25ms = 100ms */
  conn_params.min_int = 0x30; /* min_int = 0x30*1.25ms = 60ms */
  conn_params.timeout = 400;  /* timeout = 400*10ms = 4000ms */
  esp_ble_gap_update_conn_params(&conn_params);
}

void esp32_bt_gatts_auth_cmpl(const esp_bd_addr_t addr) {
  struct esp32_gatts_connection_entry *ce, *ct;
  SLIST_FOREACH_SAFE(ce, &s_conns, next, ct) {
    if (esp32_bt_addr_cmp(ce->bc.peer_addr.addr, addr) == 0 && ce->need_auth) {
      ce->need_auth = false;
      create_sessions(ce);
    }
  }
}

static void esp32_bt_gatts_ev(esp_gatts_cb_event_t ev, esp_gatt_if_t gatts_if,
                              esp_ble_gatts_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GATTS_REG_EVT: {
      const struct gatts_reg_evt_param *p = &ep->reg;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG if %d st %d app %d", gatts_if, p->status, p->app_id));
      if (p->status != ESP_GATT_OK) break;
      s_gatts_if = gatts_if;
      s_gatts_registered = true;
      esp32_bt_register_services();
      break;
    }
    case ESP_GATTS_READ_EVT: {
      const struct gatts_read_evt_param *p = &ep->read;
      LOG(LL_DEBUG, ("READ %s cid %d tid 0x%08x h %u off %d%s%s",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, (p->is_long ? " long" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      struct esp32_gatts_session_entry *sse =
          find_session(gatts_if, p->conn_id, p->handle);
      if (sse == NULL) {
        esp_ble_gatts_send_response(gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_INVALID_HANDLE, NULL);
        break;
      }
      run_on_mgos_task(gatts_if, sse, sse->se, ev, ep);
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ep->write;
      LOG(LL_DEBUG, ("WRITE %s cid %d tid 0x%08x h %u off %d len %d%s%s",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, p->len, (p->is_prep ? " prep" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      struct esp32_gatts_session_entry *sse =
          find_session(gatts_if, p->conn_id, p->handle);
      if (sse == NULL) {
        esp_ble_gatts_send_response(gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_INVALID_HANDLE, NULL);
        break;
      }
      if (!p->is_prep) {
        run_on_mgos_task(gatts_if, sse, sse->se, ev, ep);
      } else {
        struct esp32_bt_gatts_pending_write *pw = NULL;
        SLIST_FOREACH(pw, &sse->pending_writes, next) {
          if (pw->handle == p->handle) break;
        }
        if (pw == NULL) {
          pw = (struct esp32_bt_gatts_pending_write *) calloc(1, sizeof(*pw));
          pw->handle = p->handle;
          mbuf_init(&pw->value, p->len);
          SLIST_INSERT_HEAD(&sse->pending_writes, pw, next);
        }
        esp_gatt_status_t status = ESP_GATT_OK;
        esp_gatt_rsp_t rsp = {
            .handle = p->handle,
            .attr_value.handle = p->handle,
            .attr_value.offset = p->offset,
            .attr_value.len = p->len,
            .attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE,
        };
        if (p->offset != pw->value.len) {
          LOG(LL_ERROR, ("Invalid prepare write request: %u vs %u",
                         (unsigned int) pw->value.len, p->offset));
          status = ESP_GATT_INVALID_OFFSET;
        } else if (pw->value.len > MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN) {
          status = ESP_GATT_PREPARE_Q_FULL;
        } else {
          mbuf_append(&pw->value, p->value, p->len);
          memcpy(rsp.attr_value.value, p->value, p->len);
          LOG(LL_DEBUG,
              ("%d bytes pending for %u", (int) pw->value.len, pw->handle));
        }
        if (status != ESP_GATT_OK) {
          SLIST_REMOVE(&sse->pending_writes, pw, esp32_bt_gatts_pending_write,
                       next);
          mbuf_free(&pw->value);
          free(pw);
        }
        if (p->need_rsp) {
          esp_ble_gatts_send_response(gatts_if, p->conn_id, p->trans_id, status,
                                      (status == ESP_GATT_OK ? &rsp : NULL));
        }
      }
      break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT: {
      const struct gatts_exec_write_evt_param *p = &ep->exec_write;
      LOG(LL_DEBUG, ("EXEC_WRITE %s cid %d tid 0x%08x flag %d",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->exec_write_flag));
      run_on_mgos_task(gatts_if, NULL, NULL, ev, ep);
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
      run_on_mgos_task(gatts_if, NULL, NULL, ev, ep);
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
           esp32_bt_uuid_to_str(&p->service_id.id.uuid, buf),
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
           p->service_handle, esp32_bt_uuid_to_str(&p->char_uuid, buf)));
      break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT: {
      const struct gatts_add_char_descr_evt_param *p = &ep->add_char_descr;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("ADD_CHAR_DESCR st %d ah %u svch %u uuid %s", p->status,
               p->attr_handle, p->service_handle,
               esp32_bt_uuid_to_str(&p->descr_uuid, buf)));
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
      LOG(LL_INFO, ("CONNECT cid %d addr %s", p->conn_id,
                    esp32_bt_addr_to_str(p->remote_bda, buf)));
      /* Connect disables advertising. Resume, if it's enabled. */
      esp32_bt_set_is_advertising(false);
      mgos_bt_gap_set_adv_enable(mgos_bt_gap_get_adv_enable());
      bool disconnect = false;
      esp_ble_sec_act_t sec = 0;
      switch (mgos_sys_config_get_bt_gatts_min_sec_level()) {
        case MGOS_BT_GATT_PERM_LEVEL_NONE:
          break;
        case MGOS_BT_GATT_PERM_LEVEL_ENCR:
          sec = ESP_BLE_SEC_ENCRYPT_NO_MITM;
          break;
        case MGOS_BT_GATT_PERM_LEVEL_ENCR_MITM:
          sec = ESP_BLE_SEC_ENCRYPT_MITM;
          break;
      }
      if (mgos_sys_config_get_bt_gatts_require_pairing()) {
        esp32_bt_addr_to_str(p->remote_bda, buf);
        int max_devices = mgos_sys_config_get_bt_max_paired_devices();
        if (is_paired(p->remote_bda)) {
          LOG(LL_INFO, ("%s: Already paired", buf));
        } else if (!mgos_bt_gap_get_pairing_enable()) {
          LOG(LL_ERROR, ("%s: pairing required but is not allowed", buf));
          disconnect = true;
        } else if (max_devices >= 0 &&
                   mgos_bt_ble_get_num_paired_devices() >= max_devices) {
          LOG(LL_ERROR,
              ("%s: pairing required but max num devices (%d) reached", buf,
               max_devices));
          disconnect = true;
        } else {
          LOG(LL_INFO, ("%s: Begin pairing", buf));
          if (sec == 0) sec = ESP_BLE_SEC_ENCRYPT_NO_MITM;
        }
      }
      if (disconnect) {
        LOG(LL_ERROR, ("%s: dropping connection",
                       esp32_bt_addr_to_str(p->remote_bda, buf)));
        esp_ble_gap_disconnect((uint8_t *) p->remote_bda);
        break;
      }
      struct esp32_gatts_connection_entry *ce =
          (struct esp32_gatts_connection_entry *) calloc(1, sizeof(*ce));
      ce->bc.gatt_if = gatts_if;
      ce->bc.conn_id = p->conn_id;
      ce->bc.mtu = ESP_GATT_DEF_BLE_MTU_SIZE;
      memcpy(ce->bc.peer_addr.addr, p->remote_bda, ESP_BD_ADDR_LEN);
      if (sec != 0) {
        LOG(LL_DEBUG,
            ("%s: Requesting encryption%s",
             esp32_bt_addr_to_str(p->remote_bda, buf),
             (sec == ESP_BLE_SEC_ENCRYPT_MITM ? " + MITM protection" : "")));
        esp_ble_set_encryption((uint8_t *) p->remote_bda, sec);
        ce->need_auth = true;
        /* Wait for AUTH_CMPL */
      } else {
        create_sessions(ce);
      }
      SLIST_INSERT_HEAD(&s_conns, ce, next);
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      const struct gatts_disconnect_evt_param *p = &ep->disconnect;
      LOG(LL_INFO, ("DISCONNECT cid %d addr %s", p->conn_id,
                    esp32_bt_addr_to_str(p->remote_bda, buf)));

      struct esp32_gatts_connection_entry *ce =
          find_connection(gatts_if, p->conn_id);
      if (ce != NULL) {
        struct esp32_gatts_session_entry *sse, *sset;
        SLIST_FOREACH_SAFE(sse, &ce->sessions, next, sset) {
          struct esp32_bt_gatts_pending_write *pw, *pwt;
          SLIST_FOREACH_SAFE(pw, &sse->pending_writes, next, pwt) {
            mbuf_free(&pw->value);
            memset(pw, 0, sizeof(*pw));
            free(pw);
          }
          SLIST_INIT(&sse->pending_writes);
          run_on_mgos_task(gatts_if, sse, sse->se, ev, ep);
        }
        SLIST_REMOVE(&s_conns, ce, esp32_gatts_connection_entry, next);
        free(ce);
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
           esp32_bt_uuid_to_str(&p->svc_uuid, buf), p->num_handle, p->handles));
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
      run_on_mgos_task(gatts_if, NULL, se, ev, ep);
      uint16_t svch = se->attr_handles[0];
      LOG(LL_INFO,
          ("Starting BT service %s", esp32_bt_uuid_to_str(&p->svc_uuid, buf)));
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
  esp_gatts_attr_db_t *svc_descr_copy =
      (esp_gatts_attr_db_t *) calloc(num_attrs, sizeof(*svc_descr));
  memcpy(svc_descr_copy, svc_descr, num_attrs * sizeof(*svc_descr_copy));
  /* Upgrade attr security settings up to the min security level. */
  enum mgos_bt_gatt_perm_level min_level = (enum mgos_bt_gatt_perm_level)
      mgos_sys_config_get_bt_gatts_min_sec_level();
  for (size_t i = 0; i < num_attrs; i++) {
    esp_attr_desc_t *ad = &svc_descr_copy[i].att_desc;
    switch (min_level) {
      case MGOS_BT_GATT_PERM_LEVEL_NONE:
        break;
      case MGOS_BT_GATT_PERM_LEVEL_ENCR:
        if (ad->perm & (ESP_GATT_PERM_READ | ESP_GATT_PERM_READ_ENCRYPTED |
                        ESP_GATT_PERM_READ_ENC_MITM)) {
          ad->perm &= ~ESP_GATT_PERM_READ;
          ad->perm |= ESP_GATT_PERM_READ_ENCRYPTED;
        }
        if (ad->perm & (ESP_GATT_PERM_WRITE | ESP_GATT_PERM_WRITE_ENCRYPTED |
                        ESP_GATT_PERM_WRITE_ENC_MITM)) {
          ad->perm &= ~ESP_GATT_PERM_WRITE;
          ad->perm |= ESP_GATT_PERM_WRITE_ENCRYPTED;
        }
        break;
      case MGOS_BT_GATT_PERM_LEVEL_ENCR_MITM:
        if (ad->perm & (ESP_GATT_PERM_READ | ESP_GATT_PERM_READ_ENCRYPTED |
                        ESP_GATT_PERM_READ_ENC_MITM)) {
          ad->perm &= ~(ESP_GATT_PERM_READ | ESP_GATT_PERM_READ_ENCRYPTED);
          ad->perm |= ESP_GATT_PERM_READ_ENC_MITM;
        }
        if (ad->perm & (ESP_GATT_PERM_WRITE | ESP_GATT_PERM_WRITE_ENCRYPTED |
                        ESP_GATT_PERM_WRITE_ENC_MITM)) {
          ad->perm &= ~(ESP_GATT_PERM_WRITE | ESP_GATT_PERM_WRITE_ENCRYPTED);
          ad->perm |= ESP_GATT_PERM_WRITE_ENC_MITM;
        }
        break;
    }
  }
  se->svc_descr = svc_descr_copy;
  se->num_attrs = num_attrs;
  se->cb = cb;
  SLIST_INSERT_HEAD(&s_svcs, se, next);
  esp32_bt_register_services();
  return true;
}

int mgos_bt_gatts_get_num_connections(void) {
  int num = 0;
  struct esp32_gatts_connection_entry *ce;
  SLIST_FOREACH(ce, &s_conns, next) num++;
  return num;
}

bool mgos_bt_gatts_is_send_queue_empty(void) {
  return STAILQ_EMPTY(&s_inds_pending);
}

bool mgos_bt_gatts_send_indicate(esp_gatt_if_t gatts_if, uint16_t conn_id,
                                 uint16_t attr_handle, struct mg_str value,
                                 bool need_confirm) {
  esp_err_t r = ESP_OK;

  struct ind_pending *indp = calloc(1, sizeof(*indp));
  indp->gatts_if = gatts_if;
  indp->conn_id = conn_id;
  indp->handle = attr_handle;
  indp->need_confirm = need_confirm;
  indp->value = mg_strdup(value);

  /*
   * Check whether the queue was empty before the call. Note that we can't
   * just call STAILQ_INSERT_TAIL later, because CONF event might be triggered
   * even before `esp_ble_gatts_send_indicate` returns, and event handler
   * expects the queue to be non-empty.
   */
  bool empty = mgos_bt_gatts_is_send_queue_empty();

  STAILQ_INSERT_TAIL(&s_inds_pending, indp, next);

  if (empty) {
    /* Queue was empty, so send the indication/notification immediately */
    r = esp_ble_gatts_send_indicate(gatts_if, conn_id, attr_handle,
                                    indp->value.len, (uint8_t *) indp->value.p,
                                    need_confirm);
  }

  return r == ESP_OK;
}

bool mgos_bt_gatts_close(esp_gatt_if_t gatts_if, uint16_t conn_id) {
  return esp_ble_gatts_close(gatts_if, conn_id) == ESP_OK;
}

bool esp32_bt_gatts_init(void) {
  return (esp_ble_gatts_register_callback(esp32_bt_gatts_ev) == ESP_OK &&
          esp_ble_gatts_app_register(0) == ESP_OK);
}
