let GATTS = {
  EV_CONNECT: 0,
  EV_READ: 1,
  EV_WRITE: 2,
  EV_NOTIFY_MODE: 3,
  EV_IND_CONFIRM: 4,
  EV_CLOSE: 5,

  PROP_READ: 1,
  PROP_WRITE: 2,
  PROP_NOTIFY: 4,
  PROP_INDICATE: 8,

  SEC_LEVEL_NONE: 0,
  SEC_LEVEL_AUTH: 1,
  SEC_LEVEL_ENCR: 2,
  SEC_LEVEL_ENCR_MITM: 3,

  NOTIFY_MODE_OFF: 0,
  NOTIFY_MODE_NOTIFY: 1,
  NOTIFY_MODE_INDICATE: 2,

  STATUS_OK: 0,
  STATUS_INVALID_HANDLE: -1,
  STATUS_READ_NOT_PERMITTED: -2,
  STATUS_WRITE_NOT_PERMITTED: -3,
  STATUS_INSUF_AUTHENTICATION: -4,
  STATUS_REQUEST_NOT_SUPPORTED: -5,
  STATUS_INVALID_OFFSET: -6,
  STATUS_INSUF_AUTHORIZATION: -7,
  STATUS_INVALID_ATT_VAL_LENGTH: -8,
  STATUS_UNLIKELY_ERROR: -9,
  STATUS_INSUF_RESOURCES: -10,

  // ## **`GATTS.RWNI(r, w, n, i)`**
  // Helper for combining common char property bits.
  PROP_RWNI: function (r, w, n, i) {
    return (r ? GATTS.PROP_READ : 0) |
           (w ? GATTS.PROP_WRITE : 0) |
           (n ? GATTS.PROP_NOTIFY : 0) |
           (i ? GATTS.PROP_INDICATE : 0);
  },

  // ## **`GATTS.registerService(uuid, secLevel, chars, handler)`**
  // Register a GATTS service.
  // `uuid` specifies the service UUID (in string form, "1234" for 16 bit UUIDs,
  // "12345678-90ab-cdef-0123-456789abcdef" for 128-bit).
  // `sec_level` specifies the minimum required security level of the connection.
  // `chars` is an array of characteristic definitions.
  // `handler` will receive the events pertaining to the connection,
  // including reads and writes for characteristics that do not specify a handler.
  //
  // Handler function takes conenction object, event and an argument
  // and should return a status code.
  registerService: function(uuid, secLevel, chars, handler) {
    let charsC = null;
    for (let i = 0; i < chars.length; i++) {
      // Note: per-char handlers are currently not supported in JS.
      charsC = GATTS._addc(charsC, chars[i][0], chars[i][1]);
    }
    let res = GATTS._rs(uuid, secLevel, charsC, function(c, ev, ea, h) {
      let co = s2o(c, GATTS._cd);
      co._c = c;
      let eao = ea;
      if (ev === GATTS.EV_READ) {
        eao = s2o(ea, GATTS._rad);
        eao._ra = ea;
      } else if (ev === GATTS.EV_WRITE) {
        eao = s2o(ea, GATTS._wad);
      } else if (ev === GATTS.EV_NOTIFY_MODE) {
        eao = s2o(ea, GATTS._nmad);
      }
      return h(co, ev, eao);
    }, handler);
    GATTS._fch(charsC);
    return res;
  },

  sendRespData: function(c, ra, data) {
    GATTS._srd(c._c, ra._ra, data);
  },

  notify: function(c, mode, handle, data) {
    GATTS._ntfy(c._c, mode, handle, data);
  },

  _cd: ffi('void *mgos_bt_gatts_js_get_conn_def(void)')(),
  _rad: ffi('void *mgos_bt_gatts_js_get_read_arg_def(void)')(),
  _wad: ffi('void *mgos_bt_gatts_js_get_write_arg_def(void)')(),
  _nmad: ffi('void *mgos_bt_gatts_js_get_notify_mode_arg_def(void)')(),
  _addc: ffi('void *mgos_bt_gatts_js_add_char(void *, char *, int)'),
  _fch: ffi('void mgos_bt_gatts_js_free_chars(void *)'),
  _rs: ffi('bool mgos_bt_gatts_register_service(char *, int, void *, int (*)(void *, int, void *, userdata), userdata)'),
  _srd: ffi('void mgos_bt_gatts_send_resp_data_js(void *, void *, struct mg_str *)'),
  _ntfy: ffi('void mgos_bt_gatts_notify_js(void *, int, int, struct mg_str *)'),
};
