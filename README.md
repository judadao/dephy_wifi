# dephy_wifi

Reusable WiFi STA, SoftAP, and scan helper for Dephy Zephyr products.

This module is independent of product configuration structs. Products pass a
`dephy_wifi_settings_t` and receive the active IP address in a caller-owned
buffer.

## API

Include `dephy_wifi/wifi.h`.

```c
dephy_wifi_settings_t settings = {
    .wifi_ssid = "site-ap",
    .wifi_password = "secret",
    .ap_ssid = "device-setup",
    .device_ip = "192.168.4.1",
    .netmask = "255.255.255.0",
    .dhcp_enabled = 1,
};
char ip[DEPHY_WIFI_HOST_MAX];
dephy_wifi_start(&settings, ip, sizeof(ip));
```

