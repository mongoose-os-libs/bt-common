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


const char *esp32_bt_addr_to_str(const esp_bd_addr_t addr, char *out) {
  return mgos_bt_addr_to_str((const struct mgos_bt_addr *) &addr[0], 0, out);
}

int esp32_bt_addr_cmp(const esp_bd_addr_t a, const esp_bd_addr_t b) {
  return mgos_bt_addr_cmp((const struct mgos_bt_addr *) &a[0],
                          (const struct mgos_bt_addr *) &b[0]);
}

const char *bt_uuid128_to_str(const uint8_t *u, char *out) {
  sprintf(out,
          "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
          "%02x%02x%02x%02x%02x%02x",
          u[15], u[14], u[13], u[12], u[11], u[10], u[9], u[8], u[7], u[6],
          u[5], u[4], u[3], u[2], u[1], u[0]);
  return out;
}

const char *esp32_bt_uuid_to_str(const esp_bt_uuid_t *uuid, char *out) {
  return mgos_bt_uuid_to_str((struct mgos_bt_uuid *) uuid, out);
}

void mgos_bt_uuid_to_esp32(const struct mgos_bt_uuid *in, esp_bt_uuid_t *out) {
  out->len = in->len;
  memcpy(out->uuid.uuid128, in->uuid.uuid128, 16);
}

void esp32_bt_uuid_to_mgos(const esp_bt_uuid_t *in, struct mgos_bt_uuid *out) {
  out->len = in->len;
  memcpy(out->uuid.uuid128, in->uuid.uuid128, 16);
}

enum cs_log_level ll_from_status(esp_bt_status_t status) {
  return (status == ESP_BT_STATUS_SUCCESS ? LL_DEBUG : LL_ERROR);
}

static void mgos_bt_net_ev(int ev, void *evd, void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  LOG(LL_INFO, ("Network is up, disabling Bluetooth"));
  mgos_sys_config_set_bt_enable(false);
#if 0  // TODO
  char *msg = NULL;
  if (save_cfg(&mgos_sys_config, &msg)) {
    esp_bt_controller_disable();
    esp_bt_controller_deinit();
    esp_bt_controller_mem_release(ESP_BT_MODE_BLE);
  }
#endif
  (void) arg;
}

int mgos_bt_gap_get_num_paired_devices(void) {
  int count = 0;
  ble_store_util_count(BLE_STORE_OBJ_TYPE_OUR_SEC, &count);
  return count;
}

bool esp32_bt_wipe_config(void) {
  // TODO
  return false;
}

static void _on_reset(int reason) {
  LOG(LL_ERROR, ("Resetting state; reason=%d", reason));
}

static void _on_sync(void) {
  int rc;

  rc = ble_hs_util_ensure_addr(mgos_sys_config_get_bt_random_address());
  if (rc != 0) {
    LOG(LL_ERROR, ("ble_hs_util_ensure_addr rc=%d", rc));
    return;
  }

  uint8_t own_addr_type;
  rc = ble_hs_id_infer_auto(0, &own_addr_type);
  if (rc != 0) {
    LOG(LL_ERROR, ("error determining address type; rc=%d", rc));
    return;
  }

  uint8_t addr_val[6] = {0};
  rc = ble_hs_id_copy_addr(own_addr_type, addr_val, NULL);
  char addr[18] = {0};
  LOG(LL_INFO, ("BLE Device Address: %s", esp32_bt_addr_to_str(addr_val, addr)));

  mgos_bt_gap_set_adv_enable(mgos_sys_config_get_bt_adv_enable());
}

static void ble_host_task(void *param) {
  nimble_port_run();
  nimble_port_freertos_deinit();
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

  ble_hs_cfg.reset_cb = _on_reset;
  ble_hs_cfg.sync_cb = _on_sync;
  //ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;
  ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

  ble_hs_cfg.sm_sc = true;
  ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
  ble_hs_cfg.sm_bonding = mgos_sys_config_get_bt_allow_pairing();
  ble_hs_cfg.sm_mitm = true;

  ble_att_set_preferred_mtu(mgos_sys_config_get_bt_gatt_mtu());

  if (!esp32_bt_gap_init()) {
    LOG(LL_ERROR, ("GAP init failed"));
    ret = false;
    goto out;
  }
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

  nimble_port_freertos_init(ble_host_task);

  LOG(LL_INFO, ("Bluetooth init ok, MTU %d, pairing %s, %d paired devices",
                mgos_sys_config_get_bt_gatt_mtu(),
                (mgos_bt_gap_get_pairing_enable() ? "enabled" : "disabled"),
                mgos_bt_gap_get_num_paired_devices()));
  ret = true;

out:
  return ret;
}
