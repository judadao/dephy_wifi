#ifndef DEPHY_WIFI_WIFI_H
#define DEPHY_WIFI_WIFI_H

#include <stddef.h>
#include <stdint.h>

#ifndef DEPHY_WIFI_HOST_MAX
#define DEPHY_WIFI_HOST_MAX 64
#endif

#ifndef DEPHY_WIFI_SSID_MAX
#define DEPHY_WIFI_SSID_MAX 64
#endif

#ifndef DEPHY_WIFI_PASSWORD_MAX
#define DEPHY_WIFI_PASSWORD_MAX 64
#endif

typedef struct {
    char wifi_ssid[DEPHY_WIFI_SSID_MAX];
    char wifi_password[DEPHY_WIFI_PASSWORD_MAX];
    char ap_ssid[DEPHY_WIFI_SSID_MAX];
    char ap_password[DEPHY_WIFI_PASSWORD_MAX];
    char device_ip[DEPHY_WIFI_HOST_MAX];
    char gateway[DEPHY_WIFI_HOST_MAX];
    char netmask[DEPHY_WIFI_HOST_MAX];
    char dns[DEPHY_WIFI_HOST_MAX];
    uint8_t dhcp_enabled;
} dephy_wifi_settings_t;

int dephy_wifi_start(const dephy_wifi_settings_t *settings,
                     char *ip_addr,
                     size_t ip_addr_cap);
int dephy_wifi_apply_settings(const dephy_wifi_settings_t *settings);
int dephy_wifi_scan_json(char *buf, size_t buf_cap);

#endif /* DEPHY_WIFI_WIFI_H */

