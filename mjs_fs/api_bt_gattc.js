load('api_bt_gatt.js');

let GATTC = {
  EV_GRP: Event.baseNumber('GAC'),

  connect: ffi('bool mgos_bt_gattc_connect_js(char *)'),
  getConnectArg: function(evdata) { return s2o(evdata, GATTC._cd); },
  getDisconnectArg: function(evdata) { return s2o(evdata, GATTC._dd); },

  discover: ffi('bool mgos_bt_gattc_discover(int)'),
  getDiscoveryResultArg: function(evdata) { return s2o(evdata, GATTC._drad); },
  getDiscoveryDoneArg: function(evdata) { return s2o(evdata, GATTC._ddad); },

  read: ffi('bool mgos_bt_gattc_read(int, int)'),
  getReadResult: function(evdata) { return s2o(evdata, GATTC._rrd); },

  write: function(c, h, data, resp_required) {
    return GATTC._write(c, h, data, !!resp_required);
  },
  getWriteResult: function(evdata) { return s2o(evdata, GATTC._wrd); },

  setNotifyModeCCCD: ffi('bool mgos_bt_gattc_set_notify_mode_cccd(int, int, int)'),
  getNotifyArg: function(evdata) { return s2o(evdata, GATTC._nad); },

  disconnect: ffi('bool mgos_bt_gattc_disconnect(int)'),

  _cd: ffi('void *mgos_bt_gatt_js_get_connect_arg_def(void)')(),
  _dd: ffi('void *mgos_bt_gatt_js_get_disconnect_arg_def(void)')(),
  _rrd: ffi('void *mgos_bt_gattc_js_get_read_result_arg_def(void)')(),
  _wrd: ffi('void *mgos_bt_gattc_js_get_write_result_arg_def(void)')(),
  _nad: ffi('void *mgos_bt_gattc_js_get_notify_arg_def(void)')(),
  _drad: ffi('void *mgos_bt_gattc_js_get_discovery_result_arg_def(void)')(),
  _ddad: ffi('void *mgos_bt_gattc_js_get_discovery_done_arg_def(void)')(),
  _write: ffi('bool mgos_bt_gattc_write_js(int, int, struct mg_str *, bool)'),
};

GATTC.EV_CONNECT = GATTC.EV_GRP + 0;
GATTC.EV_DISCONNECT = GATTC.EV_GRP + 1;
GATTC.EV_DISCOVERY_RESULT = GATTC.EV_GRP + 2;
GATTC.EV_DISCOVERY_DONE = GATTC.EV_GRP + 3;
GATTC.EV_READ_RESULT = GATTC.EV_GRP + 4;
GATTC.EV_WRITE_RESULT = GATTC.EV_GRP + 5;
GATTC.EV_NOTIFY = GATTC.EV_GRP + 6;

GATTC.NOTIFY_MODE_OFF = 0;
GATTC.NOTIFY_MODE_NOTIFY = 1;
GATTC.NOTIFY_MODE_INDICATE = 2;
