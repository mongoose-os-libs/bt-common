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

#ifndef MOS_LIBS_GATTC_H
#define MOS_LIBS_GATTC_H

#include "mgos_bt.h"
#include "mgos_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_BT_GATTC_EVENT_BASE MGOS_EVENT_BASE('G', 'A', 'C')

enum mgos_bt_gattc_event {
  MGOS_BT_GATTC_EVENT_CONNECT =
      MGOS_BT_GATTC_EVENT_BASE,         /* struct mgos_bt_gattc_conn */
  MGOS_BT_GATTC_EVENT_DISCONNECT,       /* struct mgos_bt_gattc_conn */
  MGOS_BT_GATTC_EVENT_DISCOVERY_RESULT, /* struct mgos_bt_gattc_discovery */
  MGOS_BT_GATTC_EVENT_READ,             /* struct mgos_bt_gattc_read */
  MGOS_BT_GATTC_EVENT_NOTIFY,           /* struct mgos_bt_gattc_read */
};

struct mgos_bt_gattc_conn {
  struct mgos_bt_addr addr; /* Device address */
  int conn_id;              /* Connection ID */
  int mtu;                  /* MTU of the connection */
};

#define MGOS_BT_GATTC_INVALID_CONN_ID (-1)

struct mgos_bt_gattc_discovery {
  struct mgos_bt_addr addr; /* Device address */
  struct mgos_bt_uuid svc;  /* Service UUID */
  struct mgos_bt_uuid chr;  /* Characteristic UUID */
  uint16_t handle;          /* Characteristic handle  */
  uint8_t prop;             /* Characteristic properties */
};

struct mgos_bt_gattc_read {
  struct mgos_bt_addr addr; /* Device address */
  uint16_t handle;          /* Characteristic handle  */
  struct mg_str data;       /* Data that has been read */
};

bool mgos_bt_gattc_connect(const struct mgos_bt_addr *addr);
bool mgos_bt_gattc_discover(int conn_id);
bool mgos_bt_gattc_disconnect(int conn_id);
bool mgos_bt_gattc_read(int conn_id, uint16_t handle);
bool mgos_bt_gattc_subscribe(int conn_id, uint16_t handle);
bool mgos_bt_gattc_write(int conn_id, uint16_t handle, const void *data,
                         int len);

#ifdef __cplusplus
}
#endif

#endif /* MOS_LIBS_GATTC_H */
