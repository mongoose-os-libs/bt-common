let BLE = {
  EVENT_GRP: Event.baseNumber('BLE'),
  _srdd: ffi('void *mgos_bt_ble_get_srdd(void)')(),

  scan: ffi('bool mgos_bt_ble_scan_js(int, bool)'),
  getScanResultArg: function(evdata) { return s2o(evdata, BLE._srdd) },
};

BLE.EV_SCAN_RESULT = BLE.EVENT_GRP + 0;
BLE.EV_SCAN_STOP   = BLE.EVENT_GRP + 1;
