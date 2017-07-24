# Low level Bluetooth support

Currently contains only GATT server implmenetation for ESP32.

## Configuration section

`bt-common` library adds a `bt` configuration section with the following
settings:

```json
"bt": {
  "enable": true,       // Enabled by default. Disabled on first reboot with WiFi on
  "dev_name": "",       // Device name. If empty, value equals to device.id
  "adv_enable": true,   // Advertise our Bluetooth services
  "keep_enabled": true  // Keep enabled after successful boot with WiFi on
}
```
