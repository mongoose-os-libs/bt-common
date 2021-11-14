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

#include "mgos_bt_gatts.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "mgos.h"

#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"

#include "esp32_bt_gap.h"
#include "esp32_bt_internal.h"

#ifndef MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN
#define MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN 4096
#endif

struct esp32_bt_service_attr_info;

struct esp32_bt_gatts_service_entry {
  struct mgos_bt_uuid uuid;
  uint16_t svc_handle;
  struct esp32_bt_service_attr_info *attrs;
  uint16_t num_attrs;
  enum mgos_bt_gatt_sec_level sec_level;
  uint8_t deleting : 1;
  mgos_bt_gatts_ev_handler_t handler;
  void *handler_arg;
  // NimBLE variants of UUID, characteristic and descriptor definitions.
  ble_uuid_any_t ble_uuid;
  struct ble_gatt_chr_def *ble_chars;
  struct ble_gatt_dsc_def *ble_descrs;
  struct ble_gatt_svc_def ble_svc_def[2];
  SLIST_ENTRY(esp32_bt_gatts_service_entry) next;
};

struct esp32_bt_service_attr_info {
  struct mgos_bt_gatts_char_def def;
  ble_uuid_any_t ble_uuid;
  uint16_t handle;
};

struct esp32_bt_gatts_pending_write {
  uint16_t handle;
  struct mbuf value;
  SLIST_ENTRY(esp32_bt_gatts_pending_write) next;
};

struct esp32_bt_gatts_pending_ind {
  uint16_t handle;
  bool is_ind;
  struct mg_str value;
  STAILQ_ENTRY(esp32_bt_gatts_pending_ind) next;
};

struct esp32_bt_gatts_connection_entry;

// A set of sessions is kept for each connection, one per service.
struct esp32_bt_gatts_session_entry {
  struct esp32_bt_gatts_connection_entry *ce;
  struct mgos_bt_gatts_conn gsc;
  struct esp32_bt_gatts_service_entry *se;
  struct mbuf resp_data;
  SLIST_HEAD(pending_writes, esp32_bt_gatts_pending_write) pending_writes;
  SLIST_ENTRY(esp32_bt_gatts_session_entry) next;
};

struct esp32_bt_gatts_connection_entry {
  struct mgos_bt_gatt_conn gc;
  enum mgos_bt_gatt_sec_level sec_level;
  bool need_auth;
  bool ind_in_flight;
  /* Notifications/indications are finicky, so we keep at most one in flight. */
  int ind_queue_len;
  STAILQ_HEAD(pending_inds, esp32_bt_gatts_pending_ind) pending_inds;
  SLIST_HEAD(sessions, esp32_bt_gatts_session_entry) sessions;  // 1 per service
  SLIST_ENTRY(esp32_bt_gatts_connection_entry) next;
};

struct esp32_bt_gatts_ev_info {
  // esp_gatts_cb_event_t ev;
  // esp_ble_gatts_cb_param_t ep;
};

struct mgos_rlock_type *s_lock;
static SLIST_HEAD(s_svcs, esp32_bt_gatts_service_entry) s_svcs =
    SLIST_HEAD_INITIALIZER(s_svcs);
static SLIST_HEAD(s_conns, esp32_bt_gatts_connection_entry) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static void esp32_bt_gatts_send_next_ind_locked(
    struct esp32_bt_gatts_connection_entry *ce);
static void esp32_bt_gatts_create_sessions(
    struct esp32_bt_gatts_connection_entry *ce);
#if 0
static void esp32_bt_gatts_send_resp(struct mgos_bt_gatts_conn *gsc,
                                     uint16_t handle, uint32_t trans_id,
                                     enum mgos_bt_gatt_status status);

esp_gatt_status_t esp32_bt_gatt_get_status(enum mgos_bt_gatt_status st) {
  switch (st) {
    case MGOS_BT_GATT_STATUS_OK:
      return ESP_GATT_OK;
    case MGOS_BT_GATT_STATUS_INVALID_HANDLE:
      return ESP_GATT_INVALID_HANDLE;
    case MGOS_BT_GATT_STATUS_READ_NOT_PERMITTED:
      return ESP_GATT_READ_NOT_PERMIT;
    case MGOS_BT_GATT_STATUS_WRITE_NOT_PERMITTED:
      return ESP_GATT_WRITE_NOT_PERMIT;
    case MGOS_BT_GATT_STATUS_INSUF_AUTHENTICATION:
      return ESP_GATT_INSUF_AUTHENTICATION;
    case MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED:
      return ESP_GATT_REQ_NOT_SUPPORTED;
    case MGOS_BT_GATT_STATUS_INVALID_OFFSET:
      return ESP_GATT_INVALID_OFFSET;
    case MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION:
      return ESP_GATT_INSUF_AUTHORIZATION;
    case MGOS_BT_GATT_STATUS_INVALID_ATT_VAL_LENGTH:
      return ESP_GATT_INVALID_ATTR_LEN;
    case MGOS_BT_GATT_STATUS_UNLIKELY_ERROR:
      return ESP_GATT_ERR_UNLIKELY;
    case MGOS_BT_GATT_STATUS_INSUF_RESOURCES:
      return ESP_GATT_INSUF_RESOURCE;
  }
  return ESP_GATT_INTERNAL_ERROR;
}
#endif

#if 0
static uint16_t get_read_perm(enum mgos_bt_gatt_sec_level sec_level) {
  if (mgos_sys_config_get_bt_gatts_min_sec_level() > sec_level) {
    sec_level = mgos_sys_config_get_bt_gatts_min_sec_level();
  }
  uint16_t res = ESP_GATT_PERM_READ;
  switch (sec_level) {
    case MGOS_BT_GATT_SEC_LEVEL_NONE:
      break;
    case MGOS_BT_GATT_SEC_LEVEL_AUTH:
    case MGOS_BT_GATT_SEC_LEVEL_ENCR:
      res = ESP_GATT_PERM_READ_ENCRYPTED;
      break;
    case MGOS_BT_GATT_SEC_LEVEL_ENCR_MITM:
      res = ESP_GATT_PERM_READ_ENC_MITM;
      break;
  }
  return res;
}

static uint16_t get_write_perm(enum mgos_bt_gatt_sec_level sec_level) {
  if (mgos_sys_config_get_bt_gatts_min_sec_level() > sec_level) {
    sec_level = mgos_sys_config_get_bt_gatts_min_sec_level();
  }
  uint16_t res = ESP_GATT_PERM_WRITE;
  switch (sec_level) {
    case MGOS_BT_GATT_SEC_LEVEL_NONE:
      break;
    case MGOS_BT_GATT_SEC_LEVEL_AUTH:
    case MGOS_BT_GATT_SEC_LEVEL_ENCR:
      res = ESP_GATT_PERM_WRITE_ENCRYPTED;
      break;
    case MGOS_BT_GATT_SEC_LEVEL_ENCR_MITM:
      res = ESP_GATT_PERM_WRITE_ENC_MITM;
      break;
  }
  return res;
}
#endif

#if 0
static esp_err_t esp32_bt_register_next_attr(
    struct esp32_bt_gatts_service_entry *se) {
  if (se->num_attrs_registered >= se->num_attrs) return ESP_GATT_INVALID_OFFSET;
  const struct esp32_bt_service_attr_info *ai =
      &se->attrs[se->num_attrs_registered];
  const struct mgos_bt_gatts_char_def *cd = &ai->def;
  esp_bt_uuid_t uuid;
  mgos_bt_uuid_to_esp32(&cd->uuid_bin, &uuid);
  esp_attr_value_t val = {
      .attr_max_len = 0,
      .attr_len = 0,
      .attr_value = NULL,
  };
  esp_attr_control_t ctl = {
      .auto_rsp = ESP_GATT_RSP_BY_APP,
  };
  s_register_in_flight = true;
  esp_err_t err;
  if (!cd->is_desc) {
    esp_gatt_char_prop_t cp = 0;
    esp_gatt_perm_t perm = 0;
    if (cd->prop & MGOS_BT_GATT_PROP_READ) {
      cp |= ESP_GATT_CHAR_PROP_BIT_READ;
      perm |= get_read_perm(se->sec_level);
    }
    if (cd->prop & MGOS_BT_GATT_PROP_WRITE) {
      cp |= ESP_GATT_CHAR_PROP_BIT_WRITE;
      perm |= get_write_perm(se->sec_level);
    }
    if (cd->prop & MGOS_BT_GATT_PROP_NOTIFY) {
      cp |= ESP_GATT_CHAR_PROP_BIT_NOTIFY;
    }
    if (cd->prop & MGOS_BT_GATT_PROP_INDICATE) {
      cp |= ESP_GATT_CHAR_PROP_BIT_INDICATE;
    }
    if (cd->prop & MGOS_BT_GATT_PROP_WRITE_NR) {
      cp |= ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
      perm |= get_write_perm(se->sec_level);
    }
    err = esp_ble_gatts_add_char(se->svc_handle, &uuid, perm, cp, &val, &ctl);
  } else {
    esp_gatt_perm_t perm = 0;
    if (cd->prop & MGOS_BT_GATT_PROP_READ) {
      perm |= get_read_perm(se->sec_level);
    }
    if (cd->prop & MGOS_BT_GATT_PROP_WRITE) {
      perm |= get_write_perm(se->sec_level);
    }
    err = esp_ble_gatts_add_char_descr(se->svc_handle, &uuid, perm, &val, &ctl);
  }
  if (err != ESP_OK) {
    s_register_in_flight = false;
  }
  return err;
}
#endif

static void esp32_gatts_register_cb(struct ble_gatt_register_ctxt *ctxt,
                                    void *arg) {
  char buf[MGOS_BT_UUID_STR_LEN];

  switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
      LOG(LL_DEBUG, ("REGISTER_SVC %s sh %d",
                     esp32_bt_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                     ctxt->svc.handle));
      break;

    case BLE_GATT_REGISTER_OP_CHR:
      LOG(LL_DEBUG, ("REGISTER_CHR %s dh %d vh %d",
                     esp32_bt_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                     ctxt->chr.def_handle, ctxt->chr.val_handle));
      break;

    case BLE_GATT_REGISTER_OP_DSC:
      LOG(LL_DEBUG, ("REGISTERP_DSC %s vh %d",
                     esp32_bt_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                     ctxt->dsc.handle));
      break;
  }
}

#if 0
static struct esp32_bt_gatts_service_entry *find_service_by_uuid(
    const esp_bt_uuid_t *esp_uuid) {
  struct esp32_bt_gatts_service_entry *se;
  struct mgos_bt_uuid uuid;
  esp32_bt_uuid_to_mgos(esp_uuid, &uuid);
  SLIST_FOREACH(se, &s_svcs, next) {
    if (mgos_bt_uuid_eq(&se->uuid, &uuid)) return se;
  }
  return NULL;
}

static struct esp32_bt_gatts_service_entry *find_service_by_svc_handle(
    uint16_t svc_handle) {
  struct esp32_bt_gatts_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    if (se->svc_handle == svc_handle) return se;
  }
  return NULL;
}
#endif

static struct esp32_bt_gatts_service_entry *find_service_by_attr_handle(
    uint16_t attr_handle, struct esp32_bt_service_attr_info **ai) {
  struct esp32_bt_gatts_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    for (size_t i = 0; i < se->num_attrs; i++) {
      if (se->attrs[i].handle == attr_handle) {
        if (ai != NULL) *ai = &se->attrs[i];
        return se;
      }
    }
  }
  return NULL;
}

static struct esp32_bt_gatts_connection_entry *find_connection(
    uint16_t conn_id) {
  struct esp32_bt_gatts_connection_entry *ce = NULL;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (ce->gc.conn_id == conn_id) return ce;
  }
  return NULL;
}

static struct esp32_bt_gatts_session_entry *find_session(
    uint16_t conn_id, uint16_t handle, struct esp32_bt_service_attr_info **ai) {
  struct esp32_bt_gatts_connection_entry *ce = find_connection(conn_id);
  if (ce == NULL) return NULL;
  struct esp32_bt_gatts_service_entry *se =
      find_service_by_attr_handle(handle, ai);
  if (se == NULL) return NULL;
  struct esp32_bt_gatts_session_entry *sse;
  SLIST_FOREACH(sse, &ce->sessions, next) {
    if (sse->se == se) return sse;
  }
  return NULL;
}

static struct esp32_bt_gatts_session_entry *find_session_by_gsc(
    const struct mgos_bt_gatts_conn *gsc) {
  if (gsc == NULL) return NULL;
  struct esp32_bt_gatts_connection_entry *ce = find_connection(gsc->gc.conn_id);
  if (ce == NULL) return NULL;
  struct esp32_bt_gatts_session_entry *sse;
  SLIST_FOREACH(sse, &ce->sessions, next) {
    if (&sse->gsc == gsc) return sse;
  }
  return NULL;
}

#if 0
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

static void esp32_bt_gatts_add_pending_write(
    struct esp32_bt_gatts_session_entry *sse, uint16_t handle,
    uint32_t trans_id, uint16_t offset, struct mg_str data, bool need_rsp) {
  struct esp32_bt_gatts_pending_write *pw = NULL;
  SLIST_FOREACH(pw, &sse->pending_writes, next) {
    if (pw->handle == handle) break;
  }
  if (pw == NULL) {
    pw = (struct esp32_bt_gatts_pending_write *) calloc(1, sizeof(*pw));
    pw->handle = handle;
    mbuf_init(&pw->value, data.len);
    SLIST_INSERT_HEAD(&sse->pending_writes, pw, next);
  }
  esp_gatt_status_t status = ESP_GATT_OK;
  esp_gatt_rsp_t rsp = {
      .attr_value.handle = handle,
      .attr_value.offset = offset,
      .attr_value.len = data.len,
      .attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE,
  };
  if (offset != pw->value.len) {
    LOG(LL_ERROR, ("Invalid prepare write request: %u vs %u",
                   (unsigned int) pw->value.len, offset));
    status = ESP_GATT_INVALID_OFFSET;
  } else if (pw->value.len > MGOS_BT_GATTS_MAX_PREPARED_WRITE_LEN) {
    status = ESP_GATT_PREPARE_Q_FULL;
  } else {
    mbuf_append(&pw->value, data.p, data.len);
    memcpy(rsp.attr_value.value, data.p, data.len);
    LOG(LL_DEBUG, ("%d bytes pending for %u", (int) pw->value.len, pw->handle));
  }
  if (status != ESP_GATT_OK) {
    SLIST_REMOVE(&sse->pending_writes, pw, esp32_bt_gatts_pending_write, next);
    mbuf_free(&pw->value);
    free(pw);
  }
  if (need_rsp) {
    esp_ble_gatts_send_response(sse->ce->gatt_if, sse->ce->gc.conn_id, trans_id,
                                status, &rsp);
  }
}

static bool is_cccd(const struct esp32_bt_service_attr_info *ai) {
  return (ai->def.uuid_bin.len == 2 &&
          ai->def.uuid_bin.uuid.uuid16 == ESP_GATT_UUID_CHAR_CLIENT_CONFIG);
}
#endif

static enum mgos_bt_gatt_status esp32_bt_gatts_call_handler(
    struct esp32_bt_gatts_session_entry *sse,
    struct esp32_bt_service_attr_info *ai, enum mgos_bt_gatts_ev ev,
    void *ev_arg) {
  struct esp32_bt_gatts_service_entry *se = sse->se;
  /* Invoke attr handler if defined, fall back to service-wide handler. */
  if (ai != NULL && ai->def.handler != NULL) {
    return ai->def.handler(&sse->gsc, ev, ev_arg, ai->def.handler_arg);
  }
  return se->handler(&sse->gsc, ev, ev_arg, se->handler_arg);
}

#if 0
static void esp32_bt_gatts_do_write(struct esp32_bt_gatts_session_entry *sse,
                                    uint16_t handle, uint32_t trans_id,
                                    uint16_t offset, struct mg_str data,
                                    bool need_rsp, bool prepared) {
  char buf[MGOS_BT_UUID_STR_LEN], buf2[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gatts_service_entry *se = sse->se;
  struct esp32_bt_service_attr_info *ai = NULL;
  for (int i = 0; i < se->num_attrs; i++) {
    if (se->attrs[i].handle == handle) {
      ai = &se->attrs[i];
      break;
    }
  }
  if (ai == NULL) return;
  if (is_cccd(ai)) {
    /* Write to client config descriptor - handle notification flag change. */
    if (offset != 0 || data.len != 2) {
      LOG(LL_ERROR, ("Invalid CCCD write request: %d bytes @ %d",
                     (int) data.len, (int) offset));
      esp32_bt_gatts_send_resp(&sse->gsc, handle, trans_id,
                               MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED);
      return;
    }
    int ci = 0;
    /* Find the corresponding value. Can't fail since we found the session. */
    for (int i = 0; i < se->num_attrs; i++) {
      if (se->attrs[i].handle == handle) break;
      if (is_cccd(&se->attrs[i])) ci++;
    }
    struct esp32_bt_service_attr_info *cai = ai - 1;  // Prev entry is the char
    struct mgos_bt_gatts_notify_mode_arg arg = {
        .svc_uuid = sse->se->uuid,
        .char_uuid = cai->def.uuid_bin,
        .handle = cai->handle,
    };
    switch (data.p[0]) {
      case 1:
        arg.mode = MGOS_BT_GATT_NOTIFY_MODE_NOTIFY;
        break;
      case 2:
        arg.mode = MGOS_BT_GATT_NOTIFY_MODE_INDICATE;
        break;
    }
    enum mgos_bt_gatt_status st = esp32_bt_gatts_call_handler(
        sse, ai, MGOS_BT_GATTS_EV_NOTIFY_MODE, &arg);
    if (st == MGOS_BT_GATT_STATUS_OK) {
      memcpy(&sse->cccd_values[ci], data.p, 2);
    }
    LOG(LL_DEBUG, ("%s: notify mode %d st %d",
                   mgos_bt_uuid_to_str(&arg.char_uuid, buf), arg.mode, st));
    if (need_rsp) {
      esp32_bt_gatts_send_resp(&sse->gsc, handle, trans_id, st);
    }
    return;
  }
  struct mgos_bt_gatts_write_arg arg = {
      .svc_uuid = sse->se->uuid,
      .char_uuid = ai->def.uuid_bin,
      .handle = handle,
      .trans_id = trans_id,
      .offset = offset,
      .data = data,
      .need_rsp = true,
  };
  LOG(LL_DEBUG,
      ("WRITE %s%s cid %d tid %u h %u (%s) off %d len %d%s",
       (prepared ? "(prepared) " : ""),
       mgos_bt_addr_to_str(&sse->gsc.gc.addr, 0, buf), sse->gsc.gc.conn_id,
       arg.trans_id, arg.handle, mgos_bt_uuid_to_str(&arg.char_uuid, buf2),
       arg.offset, (int) arg.data.len, (need_rsp ? " need_rsp" : "")));
  enum mgos_bt_gatt_status st =
      esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_WRITE, &arg);
  if (need_rsp) {
    esp32_bt_gatts_send_resp(&sse->gsc, handle, trans_id, st);
  }
}
#endif

void esp32_bt_gatts_close_session(struct esp32_bt_gatts_session_entry *sse) {
  struct esp32_bt_gatts_pending_write *pw, *pwt;
  SLIST_FOREACH_SAFE(pw, &sse->pending_writes, next, pwt) {
    mbuf_free(&pw->value);
    memset(pw, 0, sizeof(*pw));
    free(pw);
  }
  SLIST_REMOVE(&sse->ce->sessions, sse, esp32_bt_gatts_session_entry, next);
  esp32_bt_gatts_call_handler(sse, NULL, MGOS_BT_GATTS_EV_DISCONNECT, NULL);
  mbuf_free(&sse->resp_data);
  memset(sse, 0, sizeof(*sse));
  free(sse);
}

#if 0
/* Executed on the main task. */
static void esp32_bt_gatts_ev_mgos(void *arg) {
  char buf[MGOS_BT_UUID_STR_LEN], buf2[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gatts_ev_info *ei = (struct esp32_bt_gatts_ev_info *) arg;
  switch (ei->ev) {
    case ESP_GATTS_CONNECT_EVT: {
      const struct gatts_connect_evt_param *p = &ei->ep.connect;
      bool disconnect = false;
      esp_ble_sec_act_t sec_act = 0;
      enum mgos_bt_gatt_sec_level sec_level = (enum mgos_bt_gatt_sec_level)
          mgos_sys_config_get_bt_gatts_min_sec_level();
      struct esp32_bt_gatts_service_entry *se;
      SLIST_FOREACH(se, &s_svcs, next) {
        if (se->sec_level > sec_level) sec_level = se->sec_level;
      }
      switch (sec_level) {
        case MGOS_BT_GATT_SEC_LEVEL_NONE:
          break;
        case MGOS_BT_GATT_SEC_LEVEL_AUTH:
        case MGOS_BT_GATT_SEC_LEVEL_ENCR:
          sec_act = ESP_BLE_SEC_ENCRYPT_NO_MITM;
          break;
        case MGOS_BT_GATT_SEC_LEVEL_ENCR_MITM:
          sec_act = ESP_BLE_SEC_ENCRYPT_MITM;
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
                   mgos_bt_gap_get_num_paired_devices() >= max_devices) {
          LOG(LL_ERROR,
              ("%s: pairing required but max num devices (%d) reached", buf,
               max_devices));
          disconnect = true;
        } else {
          LOG(LL_INFO, ("%s: Begin pairing", buf));
          if (sec_act == 0) sec_act = ESP_BLE_SEC_ENCRYPT_NO_MITM;
        }
      }
      if (disconnect) {
        LOG(LL_ERROR, ("%s: dropping connection",
                       esp32_bt_addr_to_str(p->remote_bda, buf)));
        esp_ble_gap_disconnect((uint8_t *) p->remote_bda);
        break;
      }
      struct esp32_bt_gatts_connection_entry *ce =
          (struct esp32_bt_gatts_connection_entry *) calloc(1, sizeof(*ce));
      ce->gatt_if = ei->gatts_if;
      ce->gc.conn_id = p->conn_id;
      ce->gc.mtu = ESP_GATT_DEF_BLE_MTU_SIZE;
      memcpy(ce->gc.addr.addr, p->remote_bda, ESP_BD_ADDR_LEN);
      STAILQ_INIT(&ce->pending_inds);
      SLIST_INSERT_HEAD(&s_conns, ce, next);
      if (sec_act != 0) {
        LOG(LL_DEBUG,
            ("%s: Requesting encryption%s",
             esp32_bt_addr_to_str(p->remote_bda, buf),
             (sec_act == ESP_BLE_SEC_ENCRYPT_MITM ? " + MITM protection"
                                                  : "")));
        esp_ble_set_encryption((uint8_t *) p->remote_bda, sec_act);
        ce->need_auth = true;
        /* Wait for AUTH_CMPL */
      } else {
        esp32_bt_gatts_create_sessions(ce);
      }
      break;
    }
    case ESP_GATTS_MTU_EVT: {
      struct gatts_mtu_evt_param *p = &ei->ep.mtu;
      struct esp32_bt_gatts_connection_entry *ce =
          find_connection(ei->gatts_if, p->conn_id);
      if (ce != NULL) {
        LOG(LL_DEBUG,
            ("%s: MTU %d", mgos_bt_addr_to_str(&ce->gc.addr, 0, buf), p->mtu));
        ce->gc.mtu = p->mtu;
        struct esp32_bt_gatts_session_entry *sse;
        SLIST_FOREACH(sse, &ce->sessions, next) {
          ((struct mgos_bt_gatt_conn *) &sse->gsc.gc)->mtu = p->mtu;
        }
      }
      break;
    }
    case ESP_GATTS_READ_EVT: {
      const struct gatts_read_evt_param *p = &ei->ep.read;
      struct esp32_bt_service_attr_info *ai = NULL;
      struct esp32_bt_gatts_session_entry *sse =
          find_session(ei->gatts_if, p->conn_id, p->handle, &ai);
      if (sse == NULL) {
        esp_ble_gatts_send_response(ei->gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_INVALID_HANDLE, NULL);
        break;
      }
      if (is_cccd(ai)) {
        // Read of CCCD - send notification flag value.
        struct esp32_bt_gatts_service_entry *se = sse->se;
        int ci = 0;
        // Find the corresponding value. Can't fail since we found the session.
        for (uint16_t i = 0; i < se->num_attrs; i++) {
          if (se->attrs[i].handle == p->handle) break;
          if (is_cccd(&se->attrs[i])) ci++;
        }
        esp_gatt_rsp_t rsp = {
            .attr_value =
                {
                    .handle = p->handle,
                    .offset = 0,
                    .len = 2,
                    .auth_req = ESP_GATT_AUTH_REQ_NONE,
                },
        };
        memcpy(rsp.attr_value.value, &sse->cccd_values[ci], 2);
        esp_ble_gatts_send_response(ei->gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_OK, &rsp);
        break;
      }
      struct mgos_bt_gatts_read_arg arg = {
          .svc_uuid = sse->se->uuid,
          .char_uuid = ai->def.uuid_bin,
          .handle = p->handle,
          .trans_id = p->trans_id,
          .offset = p->offset,
      };
      LOG(LL_DEBUG,
          ("READ %s cid %d tid %u h %u (%s) off %d%s%s",
           mgos_bt_addr_to_str(&sse->gsc.gc.addr, 0, buf), sse->gsc.gc.conn_id,
           arg.trans_id, arg.handle, mgos_bt_uuid_to_str(&arg.char_uuid, buf2),
           arg.offset, p->is_long ? " long" : "",
           p->need_rsp ? " need_rsp" : ""));
      if (p->is_long) {
        if (p->handle != sse->long_read_handle) {
          esp_ble_gatts_send_response(ei->gatts_if, p->conn_id, p->trans_id,
                                      ESP_GATT_INVALID_HANDLE, NULL);
          break;
        }
        const struct mgos_bt_gatt_conn *gc = &sse->gsc.gc;
        uint16_t max_len = gc->mtu - 1;
        uint16_t to_send = sse->long_read_data.len;
        if (to_send > max_len) to_send = max_len;
        esp_gatt_rsp_t rsp = {
            .attr_value =
                {
                    .handle = p->handle,
                    .offset = p->offset,
                    .len = to_send,
                    .auth_req = ESP_GATT_AUTH_REQ_NONE,
                },
        };
        memcpy(rsp.attr_value.value, sse->long_read_data.buf, to_send);
        esp_ble_gatts_send_response(s_gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_OK, &rsp);
        if (to_send == sse->long_read_data.len) {
          sse->long_read_handle = 0;
          mbuf_clear(&sse->long_read_data);
        } else {
          mbuf_remove(&sse->long_read_data, to_send);
        }
      }
      enum mgos_bt_gatt_status st =
          esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_READ, &arg);
      if (st != MGOS_BT_GATT_STATUS_OK && p->need_rsp) {
        esp32_bt_gatts_send_resp(&sse->gsc, p->handle, p->trans_id, st);
      }
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ei->ep.write;
      struct esp32_bt_gatts_session_entry *sse =
          find_session(ei->gatts_if, p->conn_id, p->handle, NULL);
      if (sse != NULL) {
        struct mg_str data = MG_MK_STR_N((char *) p->value, p->len);
        if (p->is_prep) {
          esp32_bt_gatts_add_pending_write(sse, p->handle, p->trans_id,
                                           p->offset, data, p->need_rsp);
        } else {
          esp32_bt_gatts_do_write(sse, p->handle, p->trans_id, p->offset, data,
                                  p->need_rsp, false /* is_prep */);
        }
      } else {
        esp_ble_gatts_send_response(ei->gatts_if, p->conn_id, p->trans_id,
                                    ESP_GATT_INVALID_HANDLE, NULL);
      }
      free(ei->ep.write.value);
      break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT: {
      const struct gatts_exec_write_evt_param *p = &ei->ep.exec_write;
      struct esp32_bt_gatts_connection_entry *ce =
          find_connection(ei->gatts_if, p->conn_id);
      if (ce == NULL) break;
      struct esp32_bt_gatts_session_entry *sse;
      SLIST_FOREACH(sse, &ce->sessions, next) {
        struct esp32_bt_gatts_pending_write *pw, *pwt;
        SLIST_FOREACH_SAFE(pw, &sse->pending_writes, next, pwt) {
          SLIST_REMOVE(&sse->pending_writes, pw, esp32_bt_gatts_pending_write,
                       next);
          if (p->exec_write_flag == ESP_GATT_PREP_WRITE_EXEC) {
            esp32_bt_gatts_do_write(sse, pw->handle, p->trans_id, 0,
                                    mg_mk_str_n(pw->value.buf, pw->value.len),
                                    true /* need_rsp */, true /* is_prep */);

          } else {
            /* Must be cancel - do nothing, simply discard the write. */
          }
          mbuf_free(&pw->value);
          memset(pw, 0, sizeof(*pw));
          free(pw);
        }
      }
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      const struct gatts_disconnect_evt_param *p = &ei->ep.disconnect;
      struct esp32_bt_gatts_connection_entry *ce =
          find_connection(ei->gatts_if, p->conn_id);
      if (ce == NULL) break;
      while (!SLIST_EMPTY(&ce->sessions)) {
        struct esp32_bt_gatts_session_entry *sse = SLIST_FIRST(&ce->sessions);
        esp32_bt_gatts_close_session(sse);
      }
      struct esp32_bt_gatts_pending_ind *pi, *pit;
      STAILQ_FOREACH_SAFE(pi, &ce->pending_inds, next, pit) {
        free((void *) pi->value.p);
        memset(pi, 0, sizeof(*pi));
        free(pi);
      }
      SLIST_REMOVE(&s_conns, ce, esp32_bt_gatts_connection_entry, next);
      free(ce);
      break;
    }
    case ESP_GATTS_CONF_EVT: {
      const struct gatts_conf_evt_param *p = &ei->ep.conf;
      struct esp32_bt_gatts_connection_entry *ce =
          find_connection(ei->gatts_if, p->conn_id);
      if (ce == NULL) break;
      ce->ind_in_flight = false;
      if (!STAILQ_EMPTY(&ce->pending_inds)) {
        struct esp32_bt_gatts_pending_ind *pi = STAILQ_FIRST(&ce->pending_inds);
        STAILQ_REMOVE_HEAD(&ce->pending_inds, next);
        ce->ind_queue_len--;
        /*
         * NB: p->handle is invalid for indications.
         * https://github.com/espressif/esp-idf/issues/2838
         */
        struct esp32_bt_service_attr_info *ai = NULL;
        struct esp32_bt_gatts_session_entry *sse =
            find_session(ei->gatts_if, p->conn_id, pi->handle, &ai);
        if (sse != NULL) {
          struct mgos_bt_gatts_ind_confirm_arg arg = {
              .handle = pi->handle,
              .ok = (p->status == ESP_GATT_OK),
          };
          esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_IND_CONFIRM,
                                      &arg);
        }
        free((void *) pi->value.p);
        memset(pi, 0, sizeof(*pi));
        free(pi);
      }
      esp32_bt_gatts_send_next_ind(ce);
      break;
    }
    default:
      break;
  }
  memset(ei, 0, sizeof(*ei));
  free(ei);
};

static void run_on_mgos_task(esp_gatt_if_t gatts_if, esp_gatts_cb_event_t ev,
                             esp_ble_gatts_cb_param_t *ep) {
  struct esp32_bt_gatts_ev_info *ei =
      (struct esp32_bt_gatts_ev_info *) calloc(1, sizeof(*ei));
  ei->gatts_if = gatts_if;
  ei->ev = ev;
  memcpy(&ei->ep, ep, sizeof(ei->ep));
  switch (ei->ev) {
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
  mgos_invoke_cb(esp32_bt_gatts_ev_mgos, ei, false /* from_isr */);
}

static void esp32_bt_handle_attr_add_common(esp_err_t st, uint16_t svc_handle,
                                            uint16_t attr_handle) {
  char buf[BT_UUID_STR_LEN];
  struct esp32_bt_gatts_service_entry *se =
      find_service_by_svc_handle(svc_handle);
  if (se == NULL) goto out;
  if (st != ESP_OK) {
    se->num_attrs_registered = (uint16_t) -2;
    goto out;
  }
  se->attrs[se->num_attrs_registered].handle = attr_handle;
  se->num_attrs_registered++;
  if (se->num_attrs_registered == se->num_attrs) {
    LOG(LL_INFO,
        ("Starting BT service %s", mgos_bt_uuid_to_str(&se->uuid, buf)));
    esp_ble_gatts_start_service(svc_handle);
  } else {
    if (esp32_bt_register_next_attr(se) == ESP_OK) return;
    esp32_bt_register_services();
  }
out:
  esp32_bt_register_services();
}
#endif

static void esp32_bt_gatts_create_sessions(
    struct esp32_bt_gatts_connection_entry *ce) {
  /* Create a session for each of the currently registered services. */
  struct esp32_bt_gatts_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    struct esp32_bt_gatts_session_entry *sse = calloc(1, sizeof(*sse));
    if (sse == NULL) break;
    sse->ce = ce;
    sse->se = se;
    sse->gsc.gc = ce->gc;
    sse->gsc.svc_uuid = se->uuid;
    mbuf_init(&sse->resp_data, 0);
    SLIST_INIT(&sse->pending_writes);
    enum mgos_bt_gatt_status st =
        esp32_bt_gatts_call_handler(sse, NULL, MGOS_BT_GATTS_EV_CONNECT, NULL);
    if (st != MGOS_BT_GATT_STATUS_OK) {
      /* Service rejected the connection, do not create session for it. */
      free(sse);
      continue;
    }
    SLIST_INSERT_HEAD(&ce->sessions, sse, next);
  }
}

#if 0
struct auth_cmpl_info {
  esp_bd_addr_t addr;
  bool success;
};

static void esp32_bt_gatts_auth_cmpl_mgos(void *arg) {
  char buf[MGOS_BT_ADDR_STR_LEN];
  struct auth_cmpl_info *aci = (struct auth_cmpl_info *) arg;
  struct esp32_bt_gatts_connection_entry *ce, *ct;
  esp32_bt_addr_to_str(aci->addr, buf);
  SLIST_FOREACH_SAFE(ce, &s_conns, next, ct) {
    if (esp32_bt_addr_cmp(ce->gc.addr.addr, aci->addr) != 0 || !ce->need_auth) {
      continue;
    }
    if (aci->success) {
      ce->need_auth = false;
      LOG(LL_INFO, ("%s: auth completed, starting services", buf));
      esp32_bt_gatts_create_sessions(ce);
    } else {
      LOG(LL_INFO, ("%s: auth failed, closing connection", buf));
      esp_ble_gatts_close(ce->gatt_if, ce->gc.conn_id);
    }
  }
  free(aci);
}

void esp32_bt_gatts_auth_cmpl(const esp_bd_addr_t addr, bool success) {
  struct auth_cmpl_info *aci =
      (struct auth_cmpl_info *) calloc(1, sizeof(*aci));
  memcpy(aci->addr, addr, sizeof(aci->addr));
  aci->success = success;
  mgos_invoke_cb(esp32_bt_gatts_auth_cmpl_mgos, aci, false /* from_isr */);
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
      LOG(LL_DEBUG, ("READ %s cid %d tid %u h %u off %d%s%s",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, (p->is_long ? " long" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ep->write;
      LOG(LL_DEBUG, ("WRITE %s cid %d tid %u h %u off %d len %d%s%s",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->handle, p->offset, p->len, (p->is_prep ? " prep" : ""),
                     (p->need_rsp ? " need_rsp" : "")));
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT: {
      const struct gatts_exec_write_evt_param *p = &ep->exec_write;
      LOG(LL_DEBUG, ("EXEC_WRITE %s cid %d tid %u flag %d",
                     esp32_bt_addr_to_str(p->bda, buf), p->conn_id, p->trans_id,
                     p->exec_write_flag));
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_MTU_EVT: {
      const struct gatts_mtu_evt_param *p = &ep->mtu;
      LOG(LL_DEBUG, ("MTU cid %d mtu %d", p->conn_id, p->mtu));
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_CONF_EVT: {
      const struct gatts_conf_evt_param *p = &ep->conf;
      LOG(LL_DEBUG, ("CONF cid %d st %d h %u l %u", p->conn_id, p->status,
                     p->handle, p->len));
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_UNREG_EVT: {
      LOG(LL_DEBUG, ("UNREG"));
      break;
    }
    case ESP_GATTS_CREATE_EVT: {
      const struct gatts_create_evt_param *p = &ep->create;
      struct mgos_bt_uuid svc_uuid;
      esp32_bt_uuid_to_mgos(&p->service_id.id.uuid, &svc_uuid);
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("CREATE st %d svch %d svcid %s %d%s", p->status, p->service_handle,
           mgos_bt_uuid_to_str(&svc_uuid, buf), p->service_id.id.inst_id,
           (p->service_id.is_primary ? " primary" : "")));
      s_register_in_flight = false;
      struct esp32_bt_gatts_service_entry *se =
          find_service_by_uuid(&p->service_id.id.uuid);
      if (se != NULL) {
        se->svc_handle = p->service_handle;
        se->num_attrs_registered = 0;  // Start registering attrs.
      } else {
        LOG(LL_ERROR, ("Unexpected ESP_GATTS_CREATE_EVT for %s",
                       mgos_bt_uuid_to_str(&svc_uuid, buf)));
      }
      esp32_bt_register_services();
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
      s_register_in_flight = false;
      esp32_bt_handle_attr_add_common(p->status, p->service_handle,
                                      p->attr_handle);
      break;
    }
    case ESP_GATTS_ADD_CHAR_DESCR_EVT: {
      const struct gatts_add_char_descr_evt_param *p = &ep->add_char_descr;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("ADD_DESC st %d ah %u svch %u uuid %s", p->status, p->attr_handle,
           p->service_handle, esp32_bt_uuid_to_str(&p->descr_uuid, buf)));
      s_register_in_flight = false;
      esp32_bt_handle_attr_add_common(p->status, p->service_handle,
                                      p->attr_handle);
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
      esp_ble_gatts_delete_service(p->service_handle);
      break;
    }
    case ESP_GATTS_CONNECT_EVT: {
      const struct gatts_connect_evt_param *p = &ep->connect;
      LOG(LL_INFO, ("CONNECT cid %d addr %s", p->conn_id,
                    esp32_bt_addr_to_str(p->remote_bda, buf)));
      /* Connect disables advertising. Resume, if it's enabled. */
      esp32_bt_set_is_advertising(false);
      mgos_bt_gap_set_adv_enable(mgos_bt_gap_get_adv_enable());
      run_on_mgos_task(gatts_if, ev, ep);
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      const struct gatts_disconnect_evt_param *p = &ep->disconnect;
      LOG(LL_INFO, ("DISCONNECT cid %d addr %s reason %d", p->conn_id,
                    esp32_bt_addr_to_str(p->remote_bda, buf), p->reason));
      run_on_mgos_task(gatts_if, ev, ep);
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
      LOG(ll, ("RESPONSE st %d h %d", p->status, p->handle));
      break;
    }
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      const struct gatts_add_attr_tab_evt_param *p = &ep->add_attr_tab;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("CREAT_ATTR_TAB st %d svc_uuid %s nh %d hh %p", p->status,
           esp32_bt_uuid_to_str(&p->svc_uuid, buf), p->num_handle, p->handles));
      break;
    }
    case ESP_GATTS_SET_ATTR_VAL_EVT: {
      const struct gatts_set_attr_val_evt_param *p = &ep->set_attr_val;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SET_ATTR_VAL sh %d ah %d st %d", p->srvc_handle, p->attr_handle,
               p->status));
      break;
    }
    case ESP_GATTS_SEND_SERVICE_CHANGE_EVT: {
      const struct gatts_send_service_change_evt_param *p = &ep->service_change;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SET_ATTR_VAL st %d", p->status));
      break;
    }
  }
}
#endif

int mgos_bt_gatts_get_num_connections(void) {
  int num = 0;
  struct esp32_bt_gatts_connection_entry *ce;
  SLIST_FOREACH(ce, &s_conns, next) num++;
  return num;
}

bool mgos_bt_gatts_is_send_queue_empty(void) {
  struct esp32_bt_gatts_connection_entry *ce;
  SLIST_FOREACH(ce, &s_conns, next) {
    if (!STAILQ_EMPTY(&ce->pending_inds)) return false;
  }
  return true;
}

static void esp32_bt_gatts_send_next_ind_locked(
    struct esp32_bt_gatts_connection_entry *ce) {
  int rc;
  if (ce->ind_in_flight) return;
  if (STAILQ_EMPTY(&ce->pending_inds)) return;
  struct esp32_bt_gatts_pending_ind *pi = STAILQ_FIRST(&ce->pending_inds);
  struct os_mbuf *om = ble_hs_mbuf_from_flat(pi->value.p, pi->value.len);
  ce->ind_in_flight = true;
  if (pi->is_ind) {
    rc = ble_gattc_indicate_custom(ce->gc.conn_id, pi->handle, om);
  } else {
    rc = ble_gattc_notify_custom(ce->gc.conn_id, pi->handle, om);
  }
  if (rc != 0) {
    ce->ind_in_flight = false;
    os_mbuf_free(om);
  }
}

int esp32_bt_gatts_event(const struct ble_gap_event *ev, void *arg) {
  int ret = 0;
  char buf1[MGOS_BT_UUID_STR_LEN], buf2[MGOS_BT_UUID_STR_LEN];
  LOG(LL_DEBUG,
      ("GATTS EV %d hf %d", ev->type, (int) mgos_get_free_heap_size()));
  mgos_rlock(s_lock);
  switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT: {
      uint16_t conn_id = ev->connect.conn_handle;
      struct ble_gap_conn_desc cd;
      ble_gap_conn_find(conn_id, &cd);
      LOG(LL_INFO,
          ("CONNECT h %d addr %s st %d", conn_id,
           esp32_bt_addr_to_str(&cd.peer_ota_addr, buf1), ev->connect.status));
      if (ev->connect.status != 0) break;
      struct esp32_bt_gatts_connection_entry *ce = calloc(1, sizeof(*ce));
      if (ce == NULL) {
        ble_gap_terminate(conn_id, BLE_ERR_REM_USER_CONN_TERM);
        break;
      }
      ce->gc.conn_id = conn_id;
      ce->gc.mtu = ble_att_mtu(conn_id);
      esp32_bt_addr_to_mgos(&cd.peer_ota_addr, &ce->gc.addr);
      STAILQ_INIT(&ce->pending_inds);
      SLIST_INSERT_HEAD(&s_conns, ce, next);
      ble_gattc_exchange_mtu(conn_id, NULL, NULL);
      break;
    }
    case BLE_GAP_EVENT_DISCONNECT: {
      const struct ble_gap_conn_desc *cd = &ev->disconnect.conn;
      uint16_t conn_id = cd->conn_handle;
      LOG(LL_INFO, ("DISCONNECT h %d addr %s reason %d", conn_id,
                    esp32_bt_addr_to_str(&cd->peer_ota_addr, buf1),
                    ev->disconnect.reason));
      struct esp32_bt_gatts_connection_entry *ce = find_connection(conn_id);
      if (ce == NULL) break;
      while (!SLIST_EMPTY(&ce->sessions)) {
        struct esp32_bt_gatts_session_entry *sse = SLIST_FIRST(&ce->sessions);
        esp32_bt_gatts_close_session(sse);
      }
      struct esp32_bt_gatts_pending_ind *pi, *pit;
      STAILQ_FOREACH_SAFE(pi, &ce->pending_inds, next, pit) {
        mg_strfree(&pi->value);
        memset(pi, 0, sizeof(*pi));
        free(pi);
      }
      SLIST_REMOVE(&s_conns, ce, esp32_bt_gatts_connection_entry, next);
      free(ce);
      break;
    }
    case BLE_GAP_EVENT_ENC_CHANGE: {
      break;
    }
    case BLE_GAP_EVENT_MTU: {
      struct esp32_bt_gatts_connection_entry *ce =
          find_connection(ev->mtu.conn_handle);
      if (ce == NULL) break;
      uint16_t mtu = ev->mtu.value;
      LOG(LL_DEBUG,
          ("%s: MTU %d",
           mgos_bt_addr_to_str(&ce->gc.addr, MGOS_BT_ADDR_STRINGIFY_TYPE, buf1),
           mtu));
      ce->gc.mtu = 1024;  // mtu;
      esp32_bt_gatts_create_sessions(ce);
      break;
    }
    case BLE_GAP_EVENT_SUBSCRIBE: {
      uint16_t ch = ev->subscribe.conn_handle;
      uint16_t ah = ev->subscribe.attr_handle;
      struct esp32_bt_service_attr_info *ai = NULL;
      struct esp32_bt_gatts_session_entry *sse = find_session(ch, ah, &ai);
      if (sse == NULL) break;
      struct mgos_bt_gatts_notify_mode_arg narg = {
          .svc_uuid = sse->se->uuid,
          .char_uuid = ai->def.uuid_bin,
          .handle = ev->subscribe.attr_handle,
          .mode = MGOS_BT_GATT_NOTIFY_MODE_OFF,
      };
      if (ev->subscribe.cur_notify) {
        narg.mode = MGOS_BT_GATT_NOTIFY_MODE_NOTIFY;
      } else if (ev->subscribe.cur_indicate) {
        narg.mode = MGOS_BT_GATT_NOTIFY_MODE_INDICATE;
      }
      LOG(LL_DEBUG, ("NOTIFY_MODE c %d h %d %s/%s %d", ch, ah,
                     mgos_bt_uuid_to_str(&narg.svc_uuid, buf1),
                     mgos_bt_uuid_to_str(&narg.char_uuid, buf2), narg.mode));
      esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_NOTIFY_MODE, &narg);
      break;
    }
    case BLE_GAP_EVENT_NOTIFY_TX: {
      uint16_t ch = ev->notify_tx.conn_handle;
      uint16_t ah = ev->notify_tx.attr_handle;
      struct esp32_bt_service_attr_info *ai = NULL;
      struct esp32_bt_gatts_session_entry *sse = find_session(ch, ah, &ai);
      if (sse == NULL) break;
      struct esp32_bt_gatts_connection_entry *ce = sse->ce;
      ce->ind_in_flight = false;
      LOG(LL_DEBUG,
          ("NOTIFY_TX ch %d ah %d st %d", ch, ah, ev->notify_tx.status));
      if (STAILQ_EMPTY(&ce->pending_inds)) break;  // Shouldn't happen.
      bool remove = false;
      struct esp32_bt_gatts_pending_ind *pi = STAILQ_FIRST(&ce->pending_inds);
      if (pi->is_ind) {
        // Indication raises this event twice: first with status 0 when
        // indication is sent, then again when it is acknowledged or times out.
        if (ev->notify_tx.status == 0) break;
        remove = (ev->notify_tx.status == BLE_HS_EDONE);
        struct mgos_bt_gatts_ind_confirm_arg ic_arg = {
            .handle = pi->handle,
            .ok = remove,
        };
        esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_IND_CONFIRM,
                                    &ic_arg);
      } else {
        remove = (ev->notify_tx.status == 0);
      }
      if (remove) {
        STAILQ_REMOVE_HEAD(&ce->pending_inds, next);
        mg_strfree(&pi->value);
        ce->ind_queue_len--;
        free(pi);
      }
      // Send next one or retry sending this one that failed.
      esp32_bt_gatts_send_next_ind_locked(ce);
      break;
    }
  }
  mgos_runlock(s_lock);
  return ret;
}

bool mgos_bt_gatts_disconnect(struct mgos_bt_gatts_conn *gsc) {
  if (gsc == NULL) return false;
  return ble_gap_terminate(gsc->gc.conn_id, BLE_ERR_REM_USER_CONN_TERM) == 0;
}

static int esp32_gatts_get_att_err(enum mgos_bt_gatt_status st) {
  switch (st) {
    case MGOS_BT_GATT_STATUS_OK:
      return 0;
    case MGOS_BT_GATT_STATUS_INVALID_HANDLE:
      return BLE_ATT_ERR_INVALID_HANDLE;
    case MGOS_BT_GATT_STATUS_READ_NOT_PERMITTED:
      return BLE_ATT_ERR_READ_NOT_PERMITTED;
    case MGOS_BT_GATT_STATUS_WRITE_NOT_PERMITTED:
      return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    case MGOS_BT_GATT_STATUS_INSUF_AUTHENTICATION:
      return BLE_ATT_ERR_INSUFFICIENT_AUTHEN;
    case MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED:
      return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
    case MGOS_BT_GATT_STATUS_INVALID_OFFSET:
      return BLE_ATT_ERR_INVALID_OFFSET;
    case MGOS_BT_GATT_STATUS_INSUF_AUTHORIZATION:
      return BLE_ATT_ERR_INSUFFICIENT_AUTHOR;
    case MGOS_BT_GATT_STATUS_INVALID_ATT_VAL_LENGTH:
      return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    case MGOS_BT_GATT_STATUS_UNLIKELY_ERROR:
      return BLE_ATT_ERR_UNLIKELY;
    case MGOS_BT_GATT_STATUS_INSUF_RESOURCES:
      return BLE_ATT_ERR_INSUFFICIENT_RES;
  }
  return BLE_ATT_ERR_UNLIKELY;
}

static int esp32_gatts_attr_access_cb(uint16_t conn_handle,
                                      uint16_t attr_handle,
                                      struct ble_gatt_access_ctxt *ctxt,
                                      void *arg) {
  int res = 0;
  char buf[MGOS_BT_UUID_STR_LEN], buf2[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_service_attr_info *ai = arg;
  struct esp32_bt_gatts_session_entry *sse =
      find_session(conn_handle, attr_handle, &ai);
  const ble_uuid_t *uuid = NULL;
  LOG(LL_DEBUG, ("GATTS ATTR OP %d sse %p", ctxt->op, sse));
  if (sse == NULL) return BLE_ATT_ERR_UNLIKELY;
  switch (ctxt->op) {
    case BLE_GATT_ACCESS_OP_READ_CHR:
      uuid = ctxt->chr->uuid;
      // fallthrough
    case BLE_GATT_ACCESS_OP_READ_DSC: {
      if (uuid == NULL) {
        uuid = ctxt->dsc->uuid;
      }
      struct mgos_bt_gatts_read_arg rarg = {
          .svc_uuid = sse->se->uuid,
          .handle = attr_handle,
          .trans_id = 0,
          .offset = 0,
      };
      esp32_bt_uuid_to_mgos(uuid, &rarg.char_uuid);
      enum mgos_bt_gatt_status st =
          esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_READ, &rarg);
      LOG(LL_DEBUG,
          ("READ %s ch %d ah %u (%s) -> %d %d",
           mgos_bt_addr_to_str(&sse->gsc.gc.addr, 0, buf), sse->gsc.gc.conn_id,
           rarg.handle, mgos_bt_uuid_to_str(&rarg.char_uuid, buf2), st,
           (int) sse->resp_data.len));
      res = esp32_gatts_get_att_err(st);
      if (res == 0 && sse->resp_data.len > 0) {
        os_mbuf_append(ctxt->om, sse->resp_data.buf, sse->resp_data.len);
        mbuf_clear(&sse->resp_data);
      }
      break;
    }
    case BLE_GATT_ACCESS_OP_WRITE_CHR:
      uuid = ctxt->chr->uuid;
      // fallthrough
    case BLE_GATT_ACCESS_OP_WRITE_DSC: {
      if (uuid == NULL) {
        uuid = ctxt->dsc->uuid;
      }
      char *data = NULL;
      uint16_t data_len = OS_MBUF_PKTLEN(ctxt->om);
      if (data_len > 0) {
        data = malloc(data_len);
        if (data == NULL) {
          res = BLE_ATT_ERR_UNLIKELY;
          break;
        }
        ble_hs_mbuf_to_flat(ctxt->om, data, data_len, &data_len);
      }
      struct mgos_bt_gatts_write_arg warg = {
          .svc_uuid = sse->se->uuid,
          .char_uuid = ai->def.uuid_bin,
          .handle = attr_handle,
          .data = mg_mk_str_n(data, data_len),
          .trans_id = 0,
          .offset = 0,
          .need_rsp = true,
      };
      enum mgos_bt_gatt_status st =
          esp32_bt_gatts_call_handler(sse, ai, MGOS_BT_GATTS_EV_WRITE, &warg);
      LOG(LL_DEBUG,
          ("WRITE %s ch %d ah %u (%s) len %d -> %d",
           mgos_bt_addr_to_str(&sse->gsc.gc.addr, 0, buf), sse->gsc.gc.conn_id,
           warg.handle, mgos_bt_uuid_to_str(&warg.char_uuid, buf2),
           (int) warg.data.len, st));
      res = esp32_gatts_get_att_err(st);
      free(data);
      break;
    }
  }
  return res;
}

static int esp32_bt_register_service(struct esp32_bt_gatts_service_entry *se) {
  int rc = 0;
  rc = ble_gatts_count_cfg(&se->ble_svc_def[0]);
  if (rc != 0) {
    LOG(LL_INFO, ("Count failed"));
    return rc;
  }
  rc = ble_gatts_add_svcs(&se->ble_svc_def[0]);
  if (rc != 0) {
    LOG(LL_INFO, ("Add failed"));
    return rc;
  }
  return rc;
}

static void esp32_bt_register_services(void) {
  char buf[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gatts_service_entry *se;
  SLIST_FOREACH(se, &s_svcs, next) {
    int rc = esp32_bt_register_service(se);
    if (rc != 0) {
      LOG(LL_ERROR, ("Failed to register BT service %s: %d",
                     mgos_bt_uuid_to_str(&se->uuid, buf), rc));
      continue;
    }
  }
}

bool mgos_bt_gatts_register_service(const char *svc_uuid,
                                    enum mgos_bt_gatt_sec_level sec_level,
                                    const struct mgos_bt_gatts_char_def *chars,
                                    mgos_bt_gatts_ev_handler_t handler,
                                    void *handler_arg) {
  bool res = false;
  struct esp32_bt_gatts_service_entry *se = calloc(1, sizeof(*se));
  if (se == NULL) goto out;
  if (!mgos_bt_uuid_from_str(mg_mk_str(svc_uuid), &se->uuid)) {
    LOG(LL_ERROR, ("%s: Invalid svc UUID", svc_uuid));
    goto out;
  }
  se->handler = handler;
  se->handler_arg = handler_arg;
  se->sec_level = sec_level;
  const struct mgos_bt_gatts_char_def *cd = NULL;
  // Count the number of attrs required.
  int num_chars = 0, num_descrs = 0;
  for (cd = chars; cd->uuid != NULL; cd++) {
    se->num_attrs++;
    if (!cd->is_desc) {
      num_chars++;
    } else if (cd != chars) {
      num_descrs++;
      // Add 1 desc entry per characteristic - for end marker.
      if (!(cd - 1)->is_desc) num_descrs++;
    } else {
      // Descriptors must always follow a characteristic definition
      // so a descriptor cannot be the first item in the list.
      goto out;
    }
  }
  if (num_chars == 0) goto out;
  se->attrs = calloc(se->num_attrs, sizeof(*se->attrs));
  if (se->attrs == NULL) goto out;
  se->ble_chars = calloc(num_chars + 1, sizeof(*se->ble_chars));
  if (se->ble_chars == NULL) goto out;
  if (num_descrs > 0) {
    se->ble_descrs = calloc(num_descrs + 1, sizeof(*se->ble_descrs));
    if (se->ble_descrs == NULL) goto out;
  }

  struct esp32_bt_service_attr_info *ai = se->attrs;
  struct ble_gatt_chr_def *bchr = se->ble_chars;
  struct ble_gatt_dsc_def *bdsc = se->ble_descrs;
  for (cd = chars; cd->uuid != NULL; cd++, ai++) {
    ai->def = *cd;
    if (!cd->is_uuid_bin &&
        !mgos_bt_uuid_from_str(mg_mk_str(cd->uuid), &ai->def.uuid_bin)) {
      LOG(LL_ERROR, ("%s: %s: invalid char UUID", svc_uuid, cd->uuid));
      goto out;
    }
    ai->def.is_uuid_bin = true;
    mgos_bt_uuid_to_esp32(&ai->def.uuid_bin, &ai->ble_uuid);
    if (!cd->is_desc) {
      bchr->uuid = &ai->ble_uuid.u;
      bchr->access_cb = esp32_gatts_attr_access_cb;
      bchr->arg = ai;
      bchr->min_key_size = 0;  // TODO
      bchr->val_handle = &ai->handle;
      uint8_t pp = cd->prop, ff = 0;
      if (pp & MGOS_BT_GATT_PROP_READ) ff |= BLE_GATT_CHR_F_READ;
      if (pp & MGOS_BT_GATT_PROP_WRITE) ff |= BLE_GATT_CHR_F_WRITE;
      if (pp & MGOS_BT_GATT_PROP_NOTIFY) ff |= BLE_GATT_CHR_F_NOTIFY;
      if (pp & MGOS_BT_GATT_PROP_INDICATE) ff |= BLE_GATT_CHR_F_INDICATE;
      if (pp & MGOS_BT_GATT_PROP_WRITE_NR) ff |= BLE_GATT_CHR_PROP_WRITE_NO_RSP;
      bchr->flags = ff;
      bchr++;
      if (cd != chars && (cd - 1)->is_desc) bdsc++;
    } else {
      bdsc->uuid = &ai->ble_uuid.u;
      bdsc->min_key_size = 0;  // TODO
      bdsc->access_cb = esp32_gatts_attr_access_cb;
      bdsc->arg = ai;
      uint8_t pp = cd->prop, af = 0;
      if (pp & MGOS_BT_GATT_PROP_READ) af |= BLE_ATT_F_READ;
      if (pp & MGOS_BT_GATT_PROP_WRITE) af |= BLE_ATT_F_WRITE;
      bdsc->att_flags = af;
      if (!(cd - 1)->is_desc) (bchr - 1)->descriptors = bdsc;
      bdsc++;
    }
  }

  mgos_bt_uuid_to_esp32(&se->uuid, &se->ble_uuid);
  struct ble_gatt_svc_def *bsvc = &se->ble_svc_def[0];
  bsvc->type = BLE_GATT_SVC_TYPE_PRIMARY;
  bsvc->uuid = &se->ble_uuid.u;
  bsvc->characteristics = se->ble_chars;
  se->ble_svc_def[1].type = BLE_GATT_SVC_TYPE_END;

  mgos_rlock(s_lock);
  SLIST_INSERT_HEAD(&s_svcs, se, next);
  mgos_runlock(s_lock);
  // TODO: restart if needed.
  res = true;
out:
  if (!res && se != NULL) {
    free(se->attrs);
    free(se->ble_chars);
    free(se->ble_descrs);
    free(se);
  }
  LOG(LL_INFO, ("REG %d", res));
  return res;
}

#if 0
bool mgos_bt_gatts_unregister_service(const char *uuid_str) {
  struct esp32_bt_gatts_service_entry *se;
  struct mgos_bt_uuid uuid;
  if (!mgos_bt_uuid_from_str(mg_mk_str(uuid_str), &uuid)) return false;
  SLIST_FOREACH(se, &s_svcs, next) {
    if (mgos_bt_uuid_eq(&se->uuid, &uuid)) break;
  }
  if (se == NULL) return false;
  // Remove from the list immediately in case it's re-registered.
  SLIST_REMOVE(&s_svcs, se, esp32_bt_gatts_service_entry, next);
  se->deleting = true;
  // Close the associated sessions;
  struct esp32_bt_gatts_connection_entry *ce;
  SLIST_FOREACH(ce, &s_conns, next) {
    struct esp32_bt_gatts_session_entry *sse;
    SLIST_FOREACH(sse, &ce->sessions, next) {
      if (sse->se == se) break;
    }
    if (sse == NULL) continue;
    esp32_bt_gatts_close_session(sse);
  }
  free(se->attrs);
  free(se);
  // Stop and then delete the service.
  return (esp_ble_gatts_stop_service(se->svc_handle) == ESP_OK);
}

static void esp32_bt_gatts_send_resp(struct mgos_bt_gatts_conn *gsc,
                                     uint16_t handle, uint32_t trans_id,
                                     enum mgos_bt_gatt_status st) {
  struct esp32_bt_gatts_session_entry *sse = find_session_by_gsc(gsc);
  if (sse == NULL) return;
  esp_gatt_status_t est = esp32_bt_gatt_get_status(st);
  esp_gatt_rsp_t rsp = {.handle = handle};
  LOG(LL_DEBUG, ("h %u tid %u st %d est %d", handle, trans_id, st, est));
  esp_ble_gatts_send_response(s_gatts_if, gsc->gc.conn_id, trans_id, est, &rsp);
}
#endif

void mgos_bt_gatts_send_resp_data(struct mgos_bt_gatts_conn *gsc,
                                  struct mgos_bt_gatts_read_arg *ra,
                                  struct mg_str data) {
  struct esp32_bt_gatts_session_entry *sse = find_session_by_gsc(gsc);
  if (sse == NULL) return;
  mbuf_append(&sse->resp_data, data.p, data.len);
}

void mgos_bt_gatts_notify(struct mgos_bt_gatts_conn *gsc,
                          enum mgos_bt_gatt_notify_mode mode, uint16_t handle,
                          struct mg_str data) {
  if (mode == MGOS_BT_GATT_NOTIFY_MODE_OFF) return;
  struct esp32_bt_gatts_session_entry *sse = find_session_by_gsc(gsc);
  if (sse == NULL) return;
  struct esp32_bt_gatts_pending_ind *pi = calloc(1, sizeof(*pi));
  if (pi == NULL) return;
  pi->handle = handle;
  pi->is_ind = (mode == MGOS_BT_GATT_NOTIFY_MODE_INDICATE);
  pi->value = mg_strdup(data);
  mgos_rlock(s_lock);
  STAILQ_INSERT_TAIL(&sse->ce->pending_inds, pi, next);
  sse->ce->ind_queue_len++;
  esp32_bt_gatts_send_next_ind_locked(sse->ce);
  mgos_runlock(s_lock);
}

void mgos_bt_gatts_notify_uuid(struct mgos_bt_gatts_conn *gsc,
                               const struct mgos_bt_uuid *char_uuid,
                               enum mgos_bt_gatt_notify_mode mode,
                               struct mg_str data) {
  struct esp32_bt_gatts_session_entry *sse = find_session_by_gsc(gsc);
  if (sse == NULL) return;
  struct esp32_bt_gatts_service_entry *se = sse->se;
  for (uint16_t i = 0; i < se->num_attrs; i++) {
    struct esp32_bt_service_attr_info *ai = &se->attrs[i];
    if (mgos_bt_uuid_eq(&ai->def.uuid_bin, char_uuid)) {
      mgos_bt_gatts_notify(gsc, mode, ai->handle, data);
      return;
    }
  }
}

bool esp32_bt_gatts_init(void) {
  LOG(LL_INFO, ("GATTS init, synced? %d", ble_hs_synced()));
  ble_hs_cfg.gatts_register_cb = esp32_gatts_register_cb;
  if (s_lock == NULL) {
    s_lock = mgos_rlock_create();
  }
  esp32_bt_register_services();
  return true;
}
