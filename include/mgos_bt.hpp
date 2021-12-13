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

#include <string>

#include "mgos_bt.h"

#pragma once

namespace mgos {

struct BTAddr : public mgos_bt_addr {
  BTAddr();
  BTAddr(const mgos_bt_addr *other);
  BTAddr(const mgos_bt_addr &other);
  BTAddr(const BTAddr &other) = default;
  BTAddr(const char *addr);
  BTAddr(const std::string &addr);
  BTAddr(const uint8_t *addr, bool reverse);
  bool IsZero() const;
  std::string ToString(bool stringify_type = true) const;
};

struct BTUUID : public mgos_bt_uuid {
  BTUUID();
  BTUUID(const mgos_bt_uuid *other);
  BTUUID(const mgos_bt_uuid &other);
  BTUUID(const BTUUID &other) = default;
  BTUUID(const char *uuid);
  BTUUID(const std::string &uuid);
  bool IsZero() const;
  bool IsValid() const;
  std::string ToString() const;
};

}  // namespace mgos

bool operator<(const mgos::BTAddr &a, const mgos::BTAddr &b);
bool operator<(const mgos::BTUUID &a, const mgos::BTUUID &b);
bool operator==(const mgos::BTAddr &a, const mgos::BTAddr &b);
bool operator==(const mgos::BTUUID &a, const mgos::BTUUID &b);
bool operator!=(const mgos::BTAddr &a, const mgos::BTAddr &b);
bool operator!=(const mgos::BTUUID &a, const mgos::BTUUID &b);
