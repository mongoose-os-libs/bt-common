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

#include <stdlib.h>
#include <string.h>

#include "mgos_bt_ble.h"
#include "mgos_bt_gatts.h"

/* mJS FFI helpers */

#ifdef MGOS_HAVE_MJS

#include "mjs.h"

bool mgos_bt_ble_scan_js(int duration_ms, bool active) {
  struct mgos_bt_ble_scan_opts opts = {
      .duration_ms = duration_ms, .active = active,
  };
  return mgos_bt_ble_scan(&opts);
}

static mjs_val_t bt_addr_to_obj(struct mjs *mjs, void *ap) {
  const struct mgos_bt_addr *addr = (const struct mgos_bt_addr *) ap;
  char as[MGOS_BT_ADDR_STR_LEN];
  mgos_bt_addr_to_str(addr, 0, as);
  mjs_val_t val = mjs_mk_object(mjs);
  mjs_own(mjs, &val); /* Pin the object while it is being built */
  mjs_set(mjs, val, "type", 4, mjs_mk_number(mjs, addr->type));
  mjs_set(mjs, val, "addr", 4, mjs_mk_string(mjs, as, ~0, 1));
  mjs_disown(mjs, &val);
  return val;
}

static mjs_val_t bt_uuid_to_str(struct mjs *mjs, void *ap) {
  const struct mgos_bt_uuid *addr = (const struct mgos_bt_uuid *) ap;
  char us[MGOS_BT_UUID_STR_LEN];
  mgos_bt_uuid_to_str(addr, us);
  return mjs_mk_string(mjs, us, ~0, 1);
}

/* Struct descriptor for use with s2o() */
static const struct mjs_c_struct_member srdd[] = {
    {"advData", offsetof(struct mgos_bt_ble_scan_result, adv_data),
     MJS_STRUCT_FIELD_TYPE_MG_STR, NULL},
    {"scanRsp", offsetof(struct mgos_bt_ble_scan_result, scan_rsp),
     MJS_STRUCT_FIELD_TYPE_MG_STR, NULL},
    {"rssi", offsetof(struct mgos_bt_ble_scan_result, rssi),
     MJS_STRUCT_FIELD_TYPE_INT, NULL},
    {"addr", offsetof(struct mgos_bt_ble_scan_result, addr),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_addr_to_obj},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_ble_get_srdd(void) {
  return srdd;
}

static const struct mjs_c_struct_member conn_def[] = {
    {"mtu", offsetof(struct mgos_bt_gatt_conn, mtu),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"connId", offsetof(struct mgos_bt_gatt_conn, conn_id),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"addr", offsetof(struct mgos_bt_gatt_conn, addr),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_addr_to_obj},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_gatts_js_get_conn_def(void) {
  return conn_def;
}

static const struct mjs_c_struct_member read_arg_def[] = {
    {"len", offsetof(struct mgos_bt_gatts_read_arg, len),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"offset", offsetof(struct mgos_bt_gatts_read_arg, offset),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"transId", offsetof(struct mgos_bt_gatts_read_arg, trans_id),
     MJS_STRUCT_FIELD_TYPE_INT, NULL},
    {"handle", offsetof(struct mgos_bt_gatts_read_arg, handle),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"uuid", offsetof(struct mgos_bt_gatts_read_arg, uuid),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_uuid_to_str},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_gatts_js_get_read_arg_def(void) {
  return read_arg_def;
}

static const struct mjs_c_struct_member write_arg_def[] = {
    {"data", offsetof(struct mgos_bt_gatts_write_arg, data),
     MJS_STRUCT_FIELD_TYPE_MG_STR, NULL},
    {"offset", offsetof(struct mgos_bt_gatts_write_arg, offset),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"transId", offsetof(struct mgos_bt_gatts_write_arg, trans_id),
     MJS_STRUCT_FIELD_TYPE_INT, NULL},
    {"handle", offsetof(struct mgos_bt_gatts_write_arg, handle),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"uuid", offsetof(struct mgos_bt_gatts_write_arg, uuid),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_uuid_to_str},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_gatts_js_get_write_arg_def(void) {
  return write_arg_def;
}

static mjs_val_t nm_to_int(struct mjs *mjs, void *ap) {
  const enum mgos_bt_gatt_notify_mode *mode =
      (const enum mgos_bt_gatt_notify_mode *) ap;
  return mjs_mk_number(mjs, *mode);
}

static const struct mjs_c_struct_member notify_mode_arg_def[] = {
    {"mode", offsetof(struct mgos_bt_gatts_notify_mode_arg, mode),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, nm_to_int},
    {"handle", offsetof(struct mgos_bt_gatts_notify_mode_arg, handle),
     MJS_STRUCT_FIELD_TYPE_UINT16, NULL},
    {"uuid", offsetof(struct mgos_bt_gatts_notify_mode_arg, uuid),
     MJS_STRUCT_FIELD_TYPE_CUSTOM, bt_uuid_to_str},
    {NULL, 0, MJS_STRUCT_FIELD_TYPE_INVALID, NULL},
};

const struct mjs_c_struct_member *mgos_bt_gatts_js_get_notify_mode_arg_def(
    void) {
  return notify_mode_arg_def;
}

struct mgos_bt_gatts_char_def *mgos_bt_gatts_js_add_char(
    struct mgos_bt_gatts_char_def *chars, const char *uuid, int prop) {
  struct mgos_bt_gatts_char_def *cd = chars;
  while (cd != NULL && cd->uuid != NULL) {
    cd++;
  }
  int num_chars = (cd - chars);
  chars = (struct mgos_bt_gatts_char_def *) realloc(
      chars, (num_chars + 2) * sizeof(*chars));
  cd = chars + num_chars;
  memset(cd, 0, sizeof(*cd) * 2);
  cd->uuid = strdup(uuid);
  cd->prop = (uint8_t) prop;
  return chars;
}

void mgos_bt_gatts_js_free_chars(struct mgos_bt_gatts_char_def *chars) {
  struct mgos_bt_gatts_char_def *cd = chars;
  while (cd != NULL && cd->uuid != NULL) {
    free((void *) cd->uuid);
    cd++;
  }
  free(chars);
}

void mgos_bt_gatts_send_resp_data_js(struct mgos_bt_gatts_conn *gsc,
                                     struct mgos_bt_gatts_read_arg *ra,
                                     struct mg_str *data) {
  mgos_bt_gatts_send_resp_data(gsc, ra, *data);
}

void mgos_bt_gatts_notify_js(struct mgos_bt_gatts_conn *gsc, int mode,
                             int handle, struct mg_str *data) {
  mgos_bt_gatts_notify(gsc, (enum mgos_bt_gatt_notify_mode) mode, handle,
                       *data);
}

#endif /* MGOS_HAVE_MJS */
