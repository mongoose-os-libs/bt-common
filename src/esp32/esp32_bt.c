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

#include "mgos_freertos.h"
#include "mgos_hal.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"

#include "esp_nimble_hci.h"
#include "freertos/semphr.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

uint8_t own_addr_type;
static bool s_inited = false;
static bool s_should_be_running = false;
static TaskHandle_t s_host_task_handle;
static SemaphoreHandle_t s_sem = NULL;
static struct mgos_rlock_type *s_lock = NULL;

enum esp32_bt_state {
  ESP32_BT_STOPPED = 0,
  ESP32_BT_STARTING = 1,
  ESP32_BT_STARTED = 2,
  ESP32_BT_STOPPING = 3,
};
static enum esp32_bt_state s_state = ESP32_BT_STOPPED;
struct ble_hs_stop_listener s_stop_listener;

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

const char *esp32_bt_addr_to_str(const ble_addr_t *addr, char *out) {
  struct mgos_bt_addr maddr;
  esp32_bt_addr_to_mgos(addr, &maddr);
  return mgos_bt_addr_to_str(&maddr, MGOS_BT_ADDR_STRINGIFY_TYPE, out);
}

void mgos_bt_uuid_to_esp32(const struct mgos_bt_uuid *in, ble_uuid_any_t *out) {
  out->u.type = in->len * 8;
  memcpy(out->u128.value, in->uuid.uuid128, 16);
}

void esp32_bt_uuid_to_mgos(const ble_uuid_t *in, struct mgos_bt_uuid *out) {
  out->len = in->type / 8;
  switch (in->type) {
    case BLE_UUID_TYPE_16:
      out->uuid.uuid16 = ((const ble_uuid16_t *) in)->value;
      break;
    case BLE_UUID_TYPE_32:
      out->uuid.uuid32 = ((const ble_uuid32_t *) in)->value;
      break;
    case BLE_UUID_TYPE_128:
      memcpy(out->uuid.uuid128, ((const ble_uuid128_t *) in)->value, 16);
      break;
  }
}

const char *esp32_bt_uuid_to_str(const ble_uuid_t *uuid, char *out) {
  struct mgos_bt_uuid uuidm;
  esp32_bt_uuid_to_mgos(uuid, &uuidm);
  return mgos_bt_uuid_to_str(&uuidm, out);
}

static void mgos_bt_net_ev(int ev, void *evd, void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  if (mgos_sys_config_get_bt_keep_enabled()) return;
  LOG(LL_INFO, ("Network is up, disabling Bluetooth"));
  mgos_sys_config_set_bt_enable(false);
  char *msg = NULL;
  if (save_cfg(&mgos_sys_config, &msg)) {
    mgos_bt_stop();
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
    LOG(LL_ERROR, ("BLE addr type %d error %d", own_addr_type, rc));
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

  s_state = ESP32_BT_STARTED;

  if (!s_should_be_running) {
    mgos_bt_stop();
    return;
  }

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
  esp32_bt_gap_start_advertising();
}

// Handler callback that executes host events on the mgos task.
// For efficiency, we process multiple events at a time.
static void esp32_bt_mgos_handler(void *arg) {
  int nevs = 1;
  struct ble_npl_event *ev, **ep, *evs[20] = {arg};
  struct ble_npl_eventq *q = nimble_port_get_dflt_eventq();
  // Try to get more events from the queue.
  for (ep = evs + 1; nevs < ARRAY_SIZE(evs); nevs++) {
    ev = ble_npl_eventq_get(q, 0 /* no wait */);
    if (ev == NULL) break;
    *ep++ = ev;
  }
  // Release the other task.
  xSemaphoreGive(s_sem);
  // Process the events.
  for (ep = evs; nevs > 0; ep++, nevs--) {
    ble_npl_event_run(*ep);
  }
}

static void esp32_bt_host_task(void *param) {
  if (param == NULL) {  // This is the dummy task.
    nimble_port_freertos_deinit();
    return;
  }
  s_sem = xSemaphoreCreateBinary();
  struct ble_npl_event *ev;
  struct ble_npl_eventq *q = nimble_port_get_dflt_eventq();
  while (1) {
    ev = ble_npl_eventq_get(q, BLE_NPL_TIME_FOREVER);
    while (!mgos_invoke_cb(esp32_bt_mgos_handler, ev, false /* from_isr */)) {
    }
    // Wait for the mgos task callback to run and process the event.
    xSemaphoreTake(s_sem, portMAX_DELAY);
  }
}

void esp32_bt_rlock(void) {
  mgos_rlock(s_lock);
}

void esp32_bt_runlock(void) {
  mgos_runlock(s_lock);
}

extern void ble_store_config_init(void);

static bool esp32_bt_init(void) {
  if (s_inited) {
    return true;
  }

  s_lock = mgos_rlock_create();

  bool ret = false;

  if (mgos_sys_config_get_bt_dev_name() != NULL) {
    char *dev_name = strdup(mgos_sys_config_get_bt_dev_name());
    mgos_expand_mac_address_placeholders(dev_name);
    mgos_sys_config_set_bt_dev_name(dev_name);
    free(dev_name);
  }

  esp_err_t err = esp_nimble_hci_and_controller_init();
  if (err) {
    LOG(LL_ERROR, ("BLE init failed: %d", err));
    goto out;
  }

  nimble_port_init();

  ble_hs_cfg.reset_cb = esp32_bt_reset;
  ble_hs_cfg.sync_cb = esp32_bt_synced;
  ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

  ble_hs_cfg.sm_sc = true;
  ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
  ble_hs_cfg.sm_bonding = mgos_sys_config_get_bt_allow_pairing();
  ble_hs_cfg.sm_mitm = (mgos_sys_config_get_bt_gatts_min_sec_level() ==
                        MGOS_BT_GATT_SEC_LEVEL_ENCR_MITM);

  ble_att_set_preferred_mtu(mgos_sys_config_get_bt_gatt_mtu());

  if (!mgos_sys_config_get_bt_keep_enabled()) {
    mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, mgos_bt_net_ev, NULL);
  }

  ble_store_config_init();

  // This creates the high-pri LL task and a host task.
  // We don't use the latter because its priority is too high.
  nimble_port_freertos_init(esp32_bt_host_task);
  // Instead we create our own here with priority below the main mgos task.
  xTaskCreatePinnedToCore(esp32_bt_host_task, "ble", 1024, (void *) 1,
                          MGOS_TASK_PRIORITY - 1, &s_host_task_handle,
                          NIMBLE_CORE);

  // Default INFO level log is too spammy.
  esp_log_level_set("NimBLE", ESP_LOG_WARN);

  if (!esp32_bt_gatts_init()) {
    LOG(LL_ERROR, ("%s init failed", "GATTS"));
    goto out;
  }

  mgos_bt_gap_set_adv_enable(mgos_sys_config_get_bt_adv_enable());

  LOG(LL_INFO, ("Bluetooth init ok, MTU %d, pairing %s, %d paired devices",
                mgos_sys_config_get_bt_gatt_mtu(),
                (mgos_bt_gap_get_pairing_enable() ? "enabled" : "disabled"),
                mgos_bt_gap_get_num_paired_devices()));
  ret = true;

out:
  s_inited = ret;
  return ret;
}

static void ble_hs_stop_cb(int status, void *arg) {
  LOG(LL_INFO, ("BLE stopped, status %d", status));
  s_state = ESP32_BT_STOPPED;
  if (s_should_be_running) mgos_bt_start();
  (void) arg;
}

bool mgos_bt_start(void) {
  s_should_be_running = true;
  if (s_state != ESP32_BT_STOPPED) return true;
  if (!esp32_bt_init()) return false;
  s_state = ESP32_BT_STARTING;
  if (!esp32_bt_gatts_start()) {
    LOG(LL_ERROR, ("%s start failed", "GATTS"));
    return false;
  }
  ble_hs_sched_start();
  return true;
}

bool mgos_bt_stop(void) {
  s_should_be_running = false;
  if (s_state != ESP32_BT_STARTED) return true;
  s_state = ESP32_BT_STOPPING;
  return (ble_hs_stop(&s_stop_listener, ble_hs_stop_cb, NULL) == 0);
}

void esp32_bt_restart(void) {
  if (!s_should_be_running) return;
  mgos_bt_stop();
  s_should_be_running = true;
}

static void esp32_bt_start(void *arg) {
  mgos_bt_start();
  (void) arg;
}

bool mgos_bt_common_init(void) {
  if (!mgos_sys_config_get_bt_enable()) {
    LOG(LL_INFO, ("Bluetooth is disabled"));
    return true;
  }
  // TODO(rojer): Figure out random address support under NimBLE.
  if (mgos_sys_config_get_bt_random_address()) {
    LOG(LL_ERROR, ("Random addresses are not supported, using public"));
    mgos_sys_config_set_bt_random_address(false);
  }
  esp32_bt_init();
  // Delay starting the stack until other libraries are initialized
  // and services registered to avoid unnecessary restarts.
  return mgos_invoke_cb(esp32_bt_start, NULL, false /* from_isr */);
}
