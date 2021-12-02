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

#include "mgos_bt_gattc.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "mgos.h"

#include "host/ble_gap.h"
#include "host/ble_gatt.h"

#include "esp32_bt.h"
#include "esp32_bt_internal.h"

enum esp32_bt_gattc_disc_result_entry_type {
  DISC_RESULT_SVC,
  DISC_RESULT_CHR,
  DISC_RESULT_DSC,
};

struct esp32_bt_gattc_disc_result_entry {
  enum esp32_bt_gattc_disc_result_entry_type type;
  union {
    struct ble_gatt_svc svc;
    struct ble_gatt_chr chr;
    struct ble_gatt_dsc dsc;
  };
  SLIST_ENTRY(esp32_bt_gattc_disc_result_entry) next;
};

struct esp32_bt_gattc_conn {
  struct mgos_bt_gatt_conn gc;
  bool connected;
  bool disc_in_progress;
  SLIST_HEAD(disc_results, esp32_bt_gattc_disc_result_entry) disc_results;
  SLIST_ENTRY(esp32_bt_gattc_conn) next;
};

static SLIST_HEAD(s_conns, esp32_bt_gattc_conn) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static struct esp32_bt_gattc_conn *find_conn_by_id(uint16_t conn_id) {
  struct esp32_bt_gattc_conn *conn;
  SLIST_FOREACH(conn, &s_conns, next) {
    if (conn->gc.conn_id == conn_id) return conn;
  }
  return NULL;
}

static int esp32_bt_gattc_mtu_event(uint16_t conn_id,
                                    const struct ble_gatt_error *err,
                                    uint16_t mtu, void *arg) {
  struct esp32_bt_gattc_conn *conn = arg;
  LOG(LL_DEBUG, ("MTU_FN %d st %d mtu %d", conn_id, err->status, mtu));
  if (err->status == 0) {
    conn->gc.mtu = mtu;
  }
  conn->connected = true;
  mgos_event_trigger_schedule(MGOS_BT_GATTC_EV_CONNECT, &conn->gc,
                              sizeof(conn->gc));
  return 0;
}

static uint16_t esp32_bt_gattc_get_disc_entry_handle(
    const struct esp32_bt_gattc_disc_result_entry *dre) {
  switch (dre->type) {
    case DISC_RESULT_SVC:
      return dre->svc.start_handle;
    case DISC_RESULT_CHR:
      return dre->chr.def_handle;
    case DISC_RESULT_DSC:
      return dre->dsc.handle;
  }
  return 0xffff;
}

static void esp32_bt_gattc_finish_discovery(struct esp32_bt_gattc_conn *conn,
                                            bool ok) {
  if (!conn->disc_in_progress) return;
  conn->disc_in_progress = false;
  if (ok) {
    struct esp32_bt_gattc_disc_result_entry *dre, *sdre = NULL;
    SLIST_FOREACH(dre, &conn->disc_results, next) {
      switch (dre->type) {
        case DISC_RESULT_SVC: {
          sdre = dre;
          break;
        }
        case DISC_RESULT_CHR: {
          struct mgos_bt_gattc_discovery_result_arg arg = {
              .conn = conn->gc,
              .handle = dre->chr.val_handle,
          };
          esp32_bt_uuid_to_mgos(&sdre->svc.uuid.u, &arg.svc);
          esp32_bt_uuid_to_mgos(&dre->chr.uuid.u, &arg.chr);
          mgos_event_trigger(MGOS_BT_GATTC_EV_DISCOVERY_RESULT, &arg);
          break;
        }
        case DISC_RESULT_DSC: {
          // TODO
          break;
        }
      }
    }
  }
  struct esp32_bt_gattc_disc_result_entry *dre, *dret;
  SLIST_FOREACH_SAFE(dre, &conn->disc_results, next, dret) {
    free(dre);
  }
  struct mgos_bt_gattc_discovery_done_arg arg = {
      .conn = conn->gc,
      .ok = ok,
  };
  mgos_event_trigger_schedule(MGOS_BT_GATTC_EV_DISCOVERY_DONE, &arg,
                              sizeof(arg));
}

static int esp32_bt_gattc_event(struct ble_gap_event *ev, void *arg) {
  char buf1[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gattc_conn *conn = arg;
  LOG(LL_DEBUG, ("GATTC EV %d", ev->type));
  switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT: {
      uint16_t conn_id = ev->connect.conn_handle;
      conn->gc.conn_id = conn_id;
      struct ble_gap_conn_desc cd;
      ble_gap_conn_find(conn_id, &cd);
      LOG(LL_INFO, ("CONNECT %s ch %d st %d",
                    esp32_bt_addr_to_str(&cd.peer_ota_addr, buf1), conn_id,
                    ev->connect.status));
      ble_gattc_exchange_mtu(conn_id, esp32_bt_gattc_mtu_event, conn);
      break;
    }
    case BLE_GAP_EVENT_MTU: {
      break;
    }
    case BLE_GAP_EVENT_DISCONNECT: {
      const struct ble_gap_conn_desc *cd = &ev->disconnect.conn;
      uint16_t conn_id = cd->conn_handle;
      LOG(LL_INFO, ("DISCONNECT %s ch %d reason %d",
                    esp32_bt_addr_to_str(&cd->peer_ota_addr, buf1), conn_id,
                    ev->disconnect.reason));
      SLIST_REMOVE(&s_conns, conn, esp32_bt_gattc_conn, next);
      if (conn->connected) {
        mgos_event_trigger_schedule(MGOS_BT_GATTC_EV_DISCONNECT, &conn->gc,
                                    sizeof(conn->gc));
        esp32_bt_gattc_finish_discovery(conn, false /* ok */);
      }
      free(conn);
      break;
    }
  }
  return 0;
}

bool mgos_bt_gattc_connect(const struct mgos_bt_addr *addr) {
  ble_addr_t addr2;
  mgos_bt_addr_to_esp32(addr, &addr2);
  struct esp32_bt_gattc_conn *conn = calloc(1, sizeof(*conn));
  if (conn == NULL) return false;
  conn->gc.addr = *addr;
  conn->gc.conn_id = 0xffff;
  SLIST_INIT(&conn->disc_results);
  int rc = ble_gap_connect(own_addr_type, &addr2, 1000 /* duration_ms */,
                           NULL /* params */, esp32_bt_gattc_event, conn);
  if (rc != 0) {
    free(conn);
    return false;
  }
  SLIST_INSERT_HEAD(&s_conns, conn, next);
  return true;
}

bool mgos_bt_gattc_read(uint16_t conn_id, uint16_t handle) {
  return false;
}

bool mgos_bt_gattc_subscribe(uint16_t conn_id, uint16_t handle) {
  struct esp32_bt_gattc_conn *conn = find_conn_by_id(conn_id);
  if (conn == NULL) return false;
  return false;
}

bool mgos_bt_gattc_write(uint16_t conn_id, uint16_t handle, struct mg_str data,
                         bool resp_required) {
  struct esp32_bt_gattc_conn *conn = find_conn_by_id(conn_id);
  if (conn == NULL) return false;
  return false;
}

static int esp32_bt_gattc_add_disc_result_entry(
    struct esp32_bt_gattc_conn *conn,
    const struct esp32_bt_gattc_disc_result_entry *cdre) {
  struct esp32_bt_gattc_disc_result_entry *ndre = calloc(1, sizeof(*cdre));
  if (ndre == NULL) {
    esp32_bt_gattc_finish_discovery(conn, false /* ok */);
    return BLE_ATT_ERR_INSUFFICIENT_RES;
  }
  *ndre = *cdre;
  // Find insertion point: keep the list ordered by handle.
  uint16_t h = esp32_bt_gattc_get_disc_entry_handle(ndre);
  struct esp32_bt_gattc_disc_result_entry *dre = NULL, *last_dre = NULL;
  SLIST_FOREACH(dre, &conn->disc_results, next) {
    if (esp32_bt_gattc_get_disc_entry_handle(dre) > h) break;
    last_dre = dre;
  }
  if (last_dre == NULL) {
    SLIST_INSERT_HEAD(&conn->disc_results, ndre, next);
  } else {
    SLIST_INSERT_AFTER(last_dre, ndre, next);
  }
  return 0;
}

static int esp32_bt_gattc_disc_chr_ev(uint16_t conn_id,
                                      const struct ble_gatt_error *err,
                                      const struct ble_gatt_chr *chr,
                                      void *arg) {
  int ret = 0;
  char buf[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gattc_conn *conn = arg;
  switch (err->status) {
    case 0:
      LOG(LL_DEBUG, ("DISC_CHR ch %d uuid %s dh %d vh %d", conn_id,
                     esp32_bt_uuid_to_str(&chr->uuid.u, buf), chr->def_handle,
                     chr->val_handle));
      struct esp32_bt_gattc_disc_result_entry dre = {
          .type = DISC_RESULT_CHR,
          .chr = *chr,
      };
      ret = esp32_bt_gattc_add_disc_result_entry(conn, &dre);
      break;
    case BLE_HS_EDONE: {
      // TODO: Discover descriptors?

      esp32_bt_gattc_finish_discovery(conn, true /* ok */);
      break;
    }
    default: {
      esp32_bt_gattc_finish_discovery(conn, false /* ok */);
    }
  }
  return ret;
}

static int esp32_bt_gattc_disc_svc_ev(uint16_t conn_id,
                                      const struct ble_gatt_error *err,
                                      const struct ble_gatt_svc *svc,
                                      void *arg) {
  int ret = 0;
  char buf[MGOS_BT_UUID_STR_LEN];
  struct esp32_bt_gattc_conn *conn = arg;
  switch (err->status) {
    case 0:
      LOG(LL_DEBUG, ("DISC_SVC ch %d uuid %s sh %d eh %d", conn_id,
                     esp32_bt_uuid_to_str(&svc->uuid.u, buf), svc->start_handle,
                     svc->end_handle));
      struct esp32_bt_gattc_disc_result_entry dre = {
          .type = DISC_RESULT_SVC,
          .svc = *svc,
      };
      ret = esp32_bt_gattc_add_disc_result_entry(conn, &dre);
      break;
    case BLE_HS_EDONE: {
      if (SLIST_EMPTY(&conn->disc_results)) {
        // No services.
        esp32_bt_gattc_finish_discovery(conn, true /* ok */);
      }
      uint16_t sh = SLIST_FIRST(&conn->disc_results)->svc.start_handle;
      if (ble_gattc_disc_all_chrs(conn_id, sh, 0xffff,
                                  esp32_bt_gattc_disc_chr_ev, conn) != 0) {
        esp32_bt_gattc_finish_discovery(conn, false /* ok */);
      }
      break;
    }
    default: {
      esp32_bt_gattc_finish_discovery(conn, false /* ok */);
    }
  }
  return ret;
}

bool mgos_bt_gattc_discover(uint16_t conn_id) {
  struct esp32_bt_gattc_conn *conn = find_conn_by_id(conn_id);
  if (conn == NULL) return false;
  if (!conn->connected || conn->disc_in_progress) return false;
  conn->disc_in_progress = true;
  if (ble_gattc_disc_all_svcs(conn_id, esp32_bt_gattc_disc_svc_ev, conn) != 0) {
    conn->disc_in_progress = false;
  }
  return true;
}

bool mgos_bt_gattc_disconnect(uint16_t conn_id) {
  return (ble_gap_terminate(conn_id, BLE_ERR_REM_USER_CONN_TERM) == 0);
}
