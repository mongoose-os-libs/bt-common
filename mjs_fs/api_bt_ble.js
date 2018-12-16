let BLE = {
  EV_GRP: Event.baseNumber('BLE'),

  scan: ffi('bool mgos_bt_ble_scan_js(int, bool)'),
  getScanResultArg: function(evdata) { return s2o(evdata, BLE._srdd) },

  // ## **`BLE.parseName(advData)`**
  // Parse name from adv data. Tries to get long, falls back to short.
  parseName: ffi('char *mgos_bt_ble_parse_name_js(struct mg_str *)'),

  _srdd: ffi('void *mgos_bt_ble_get_srdd(void)')(),
};

BLE.EV_SCAN_RESULT = BLE.EV_GRP + 0;
BLE.EV_SCAN_STOP   = BLE.EV_GRP + 1;
