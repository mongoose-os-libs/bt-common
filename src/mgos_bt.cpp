/*
 * Copyright (c) 2021 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_bt.hpp"

#include <cstring>

namespace mgos {

BTAddr::BTAddr() {
  std::memset(addr, 0, sizeof(addr));
  type = MGOS_BT_ADDR_TYPE_NONE;
}

BTAddr::BTAddr(const mgos_bt_addr *other) {
  std::memcpy(addr, other->addr, sizeof(addr));
  type = other->type;
}

BTAddr::BTAddr(const mgos_bt_addr &other) : BTAddr(&other) {
}

BTAddr::BTAddr(const char *addr) : BTAddr() {
  mgos_bt_addr_from_str(mg_mk_str(addr), this);
}

BTAddr::BTAddr(const std::string &addr) : BTAddr() {
  mgos_bt_addr_from_str(mg_mk_str_n(addr.data(), addr.size()), this);
}

BTAddr::BTAddr(const uint8_t *addr_, bool reverse) {
  if (reverse) {
    addr[0] = addr_[5];
    addr[1] = addr_[4];
    addr[2] = addr_[3];
    addr[3] = addr_[2];
    addr[4] = addr_[1];
    addr[5] = addr_[0];
  } else {
    addr[0] = addr_[0];
    addr[1] = addr_[1];
    addr[2] = addr_[2];
    addr[3] = addr_[3];
    addr[4] = addr_[4];
    addr[5] = addr_[5];
  }
}

bool BTAddr::IsZero() const {
  return mgos_bt_addr_is_zero(this);
}

std::string BTAddr::ToString(bool stringify_type) const {
  char buf[MGOS_BT_ADDR_STR_LEN];
  uint32_t flags = (stringify_type ? MGOS_BT_ADDR_STRINGIFY_TYPE : 0);
  return mgos_bt_addr_to_str(this, flags, buf);
}

BTUUID::BTUUID() {
  std::memset(&uuid, 0, sizeof(uuid));
  len = 0;
}

BTUUID::BTUUID(const mgos_bt_uuid *other) {
  std::memcpy(&uuid, &other->uuid, sizeof(uuid));
  len = other->len;
}

BTUUID::BTUUID(const mgos_bt_uuid &other) : BTUUID(&other) {
}

BTUUID::BTUUID(const char *uuid) : BTUUID() {
  mgos_bt_uuid_from_str(mg_mk_str(uuid), this);
}

BTUUID::BTUUID(const std::string &uuid) : BTUUID() {
  mgos_bt_uuid_from_str(mg_mk_str_n(uuid.data(), uuid.size()), this);
}

bool BTUUID::IsZero() const {
  return mgos_bt_uuid_is_zero(this);
}

bool BTUUID::IsValid() const {
  return (len == 2 || len == 4 || len == 16);
}

std::string BTUUID::ToString() const {
  char buf[MGOS_BT_UUID_STR_LEN];
  return mgos_bt_uuid_to_str(this, buf);
}
}  // namespace mgos

bool operator<(const mgos::BTAddr &a, const mgos::BTAddr &b) {
  return (mgos_bt_addr_cmp(&a, &b) < 0);
};

bool operator<(const mgos::BTUUID &a, const mgos::BTUUID &b) {
  return (mgos_bt_uuid_cmp(&a, &b) < 0);
};

bool operator==(const mgos::BTAddr &a, const mgos::BTAddr &b) {
  return (mgos_bt_addr_cmp(&a, &b) == 0);
};

bool operator==(const mgos::BTUUID &a, const mgos::BTUUID &b) {
  return mgos_bt_uuid_eq(&a, &b);
};

bool operator!=(const mgos::BTAddr &a, const mgos::BTAddr &b) {
  return (mgos_bt_addr_cmp(&a, &b) != 0);
};

bool operator!=(const mgos::BTUUID &a, const mgos::BTUUID &b) {
  return !mgos_bt_uuid_eq(&a, &b);
};
