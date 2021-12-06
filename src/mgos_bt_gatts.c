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

static enum mgos_bt_gatt_status mgos_bt_gatts_read_n(
    struct mgos_bt_gatts_conn *c, enum mgos_bt_gatts_ev ev, void *ev_arg,
    void *handler_arg, size_t n) {
  if (ev != MGOS_BT_GATTS_EV_READ) {
    return MGOS_BT_GATT_STATUS_REQUEST_NOT_SUPPORTED;
  }
  struct mgos_bt_gatts_read_arg *arg = ev_arg;
  mgos_bt_gatts_send_resp_data(c, arg, mg_mk_str_n((void *) &handler_arg, n));
  (void) c;
  (void) ev_arg;
  return MGOS_BT_GATT_STATUS_OK;
}

enum mgos_bt_gatt_status mgos_bt_gatts_read_1(struct mgos_bt_gatts_conn *c,
                                              enum mgos_bt_gatts_ev ev,
                                              void *ev_arg, void *handler_arg) {
  return mgos_bt_gatts_read_n(c, ev, ev_arg, handler_arg, 1);
}

enum mgos_bt_gatt_status mgos_bt_gatts_read_2(struct mgos_bt_gatts_conn *c,
                                              enum mgos_bt_gatts_ev ev,
                                              void *ev_arg, void *handler_arg) {
  return mgos_bt_gatts_read_n(c, ev, ev_arg, handler_arg, 2);
}

enum mgos_bt_gatt_status mgos_bt_gatts_read_4(struct mgos_bt_gatts_conn *c,
                                              enum mgos_bt_gatts_ev ev,
                                              void *ev_arg, void *handler_arg) {
  return mgos_bt_gatts_read_n(c, ev, ev_arg, handler_arg, 4);
}
