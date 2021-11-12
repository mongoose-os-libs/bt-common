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

#include "esp32_bt.h"
#include "esp32_bt_gap.h"
#include "esp32_bt_internal.h"

#include <stdbool.h>
#include <stdlib.h>

#include "common/mg_str.h"

#include "mgos_hal.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"

#include "esp_nimble_hci.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

uint8_t own_addr_type;

void mgos_bt_addr_to_esp32(const struct mgos_bt_addr *in, ble_addr_t *out) {
  switch (in->type) {
    case MGOS_BT_ADDR_TYPE_NONE:
    case MGOS_BT_ADDR_TYPE_PUBLIC:
      out->type = BLE_ADDR_PUBLIC;
      break;
    case MGOS_BT_ADDR_TYPE_RANDOM_STATIC:
    case MGOS_BT_ADDR_TYPE_RANDOM_RESOLVABLE:
    case MGOS_BT_ADDR_TYPE_RANDOM_NON_RESOLVABLE:
      out->type = BLE_ADDR_RANDOM;
      break;
  }
  out->val[0] = in->addr[5];
  out->val[1] = in->addr[4];
  out->val[2] = in->addr[3];
  out->val[3] = in->addr[2];
  out->val[4] = in->addr[1];
  out->val[5] = in->addr[0];
}

void esp32_bt_addr_to_mgos(const ble_addr_t *in, struct mgos_bt_addr *out) {
  out->type = MGOS_BT_ADDR_TYPE_NONE;
  switch (in->type) {
    case BLE_ADDR_PUBLIC:
      out->type = MGOS_BT_ADDR_TYPE_PUBLIC;
      break;
    case BLE_ADDR_RANDOM:
      if (BLE_ADDR_IS_STATIC(in)) {
        out->type = MGOS_BT_ADDR_TYPE_RANDOM_STATIC;
      } else if (BLE_ADDR_IS_RPA(in)) {
        out->type = MGOS_BT_ADDR_TYPE_RANDOM_RESOLVABLE;
      } else if (BLE_ADDR_IS_NRPA(in)) {
        out->type = MGOS_BT_ADDR_TYPE_RANDOM_NON_RESOLVABLE;
      }
      break;
  }
  out->addr[0] = in->val[5];
  out->addr[1] = in->val[4];
  out->addr[2] = in->val[3];
  out->addr[3] = in->val[2];
  out->addr[4] = in->val[1];
  out->addr[5] = in->val[0];
}

void mgos_bt_uuid_to_esp32(const struct mgos_bt_uuid *in, ble_uuid_any_t *out) {
  out->u.type = in->len * 8;
  memcpy(out->u128.value, in->uuid.uuid128, 16);
}

void esp32_bt_uuid_to_mgos(const ble_uuid_any_t *in, struct mgos_bt_uuid *out) {
  out->len = in->u.type / 8;
  memcpy(out->uuid.uuid128, in->u128.value, 16);
}

const char *esp32_bt_uuid_to_str(const ble_uuid_t *uuid, char *out) {
  struct mgos_bt_uuid uuidm;
  esp32_bt_uuid_to_mgos((const ble_uuid_any_t *) uuid, &uuidm);
  return mgos_bt_uuid_to_str(&uuidm, out);
}

static void mgos_bt_net_ev(int ev, void *evd, void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  if (mgos_sys_config_get_bt_keep_enabled()) return;
  LOG(LL_INFO, ("Network is up, disabling Bluetooth"));
  mgos_sys_config_set_bt_enable(false);
  char *msg = NULL;
  if (save_cfg(&mgos_sys_config, &msg)) {
    nimble_port_stop();
  }
  (void) arg;
}

bool mgos_bt_get_device_address(struct mgos_bt_addr *addr) {
  int rc = ble_hs_id_infer_auto(mgos_sys_config_get_bt_random_address(),
                                &own_addr_type);
  if (rc != 0) {
    LOG(LL_ERROR, ("error determining address type; rc=%d", rc));
    return false;
  }
  ble_addr_t baddr = {0};
  int is_nrpa = false;
  rc = ble_hs_id_copy_addr(own_addr_type, baddr.val, &is_nrpa);
  if (rc != 0) {
    LOG(LL_ERROR, ("BLE addr error %d", rc));
    return false;
  }
  switch (own_addr_type) {
    case BLE_OWN_ADDR_PUBLIC:
      baddr.type = BLE_ADDR_PUBLIC;
      break;
    case BLE_OWN_ADDR_RANDOM:
    case BLE_OWN_ADDR_RPA_RANDOM_DEFAULT:
    case BLE_OWN_ADDR_RPA_PUBLIC_DEFAULT:
      baddr.type = BLE_ADDR_RANDOM;
      break;
    default:
      return false;
  }
  esp32_bt_addr_to_mgos(&baddr, addr);
  return true;
}

static void esp32_bt_reset(int reason) {
  LOG(LL_ERROR, ("Resetting state; reason=%d", reason));
}

static void esp32_bt_synced(void) {
  int rc;

  bool privacy = mgos_sys_config_get_bt_random_address();

  rc = ble_hs_util_ensure_addr(privacy);
  if (rc != 0) {
    LOG(LL_ERROR, ("ble_hs_util_ensure_addr rc=%d", rc));
    return;
  }

  struct mgos_bt_addr addr;
  if (mgos_bt_get_device_address(&addr)) {
    char addr_str[MGOS_BT_ADDR_STR_LEN] = {0};
    LOG(LL_INFO,
        ("BLE Device Address: %s",
         mgos_bt_addr_to_str(&addr, MGOS_BT_ADDR_STRINGIFY_TYPE, addr_str)));
  }

  if (!esp32_bt_gap_init()) {
    LOG(LL_ERROR, ("%s init failed", "GAP"));
  }
  mgos_bt_gap_set_adv_enable(mgos_sys_config_get_bt_adv_enable());
}

static void ble_host_task(void *param) {
  LOG(LL_DEBUG, ("BLE task %s", "running"));
  nimble_port_run();
  nimble_port_freertos_deinit();
  LOG(LL_DEBUG, ("BLE task %s", "exiting"));
}

static void esp32_bt_start(void *arg) {
  LOG(LL_DEBUG, ("BLE task %s", "starting"));
  if (!esp32_bt_gatts_init()) {
    LOG(LL_ERROR, ("%s init failed", "GATTS"));
  }
  nimble_port_freertos_init(ble_host_task);
  ble_hs_sched_start();
  (void) arg;
}

extern void ble_store_config_init(void);

bool mgos_bt_common_init(void) {
  bool ret = false;
  if (!mgos_sys_config_get_bt_enable()) {
    LOG(LL_INFO, ("Bluetooth is disabled"));
    return true;
  }

  if (mgos_sys_config_get_bt_dev_name() != NULL) {
    char *dev_name = strdup(mgos_sys_config_get_bt_dev_name());
    mgos_expand_mac_address_placeholders(dev_name);
    mgos_sys_config_set_bt_dev_name(dev_name);
    free(dev_name);
  }

  esp_err_t err = esp_nimble_hci_and_controller_init();
  if (err) {
    LOG(LL_ERROR, ("BT init failed: %d", err));
    goto out;
  }

  nimble_port_init();

  ble_hs_cfg.reset_cb = esp32_bt_reset;
  ble_hs_cfg.sync_cb = esp32_bt_synced;
  // ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;
  ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

  ble_hs_cfg.sm_sc = true;
  ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
  ble_hs_cfg.sm_bonding = mgos_sys_config_get_bt_allow_pairing();
  ble_hs_cfg.sm_mitm = true;

  ble_att_set_preferred_mtu(mgos_sys_config_get_bt_gatt_mtu());

#if 0
  if (!esp32_bt_gattc_init()) {
    LOG(LL_ERROR, ("GATTC init failed"));
    ret = false;
    goto out;
  }

  if (!esp32_bt_gatts_init()) {
    LOG(LL_ERROR, ("GATTS init failed"));
    ret = false;
    goto out;
  }
#endif
  if (!mgos_sys_config_get_bt_keep_enabled()) {
    mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, mgos_bt_net_ev, NULL);
  }

  ble_store_config_init();

  // Delay starting the stack until other libraries are initialized
  // and services registered.
  mgos_invoke_cb(esp32_bt_start, NULL, false /* from_isr */);

  LOG(LL_INFO, ("Bluetooth init ok, MTU %d, pairing %s, %d paired devices",
                mgos_sys_config_get_bt_gatt_mtu(),
                (mgos_bt_gap_get_pairing_enable() ? "enabled" : "disabled"),
                mgos_bt_gap_get_num_paired_devices()));
  ret = true;

out:
  return ret;
}
