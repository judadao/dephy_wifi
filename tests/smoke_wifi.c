#include <stdio.h>
#include <string.h>

#include "dephy_wifi/wifi.h"

int main(void)
{
    dephy_wifi_settings_t settings;
    char ip[DEPHY_WIFI_HOST_MAX];
    char scan[256];

    memset(&settings, 0, sizeof(settings));
    snprintf(settings.device_ip, sizeof(settings.device_ip), "192.168.4.1");

    if (dephy_wifi_start(&settings, ip, sizeof(ip)) != 0) {
        return 1;
    }
    if (strcmp(ip, "192.168.4.1") != 0) {
        fprintf(stderr, "unexpected ip: %s\n", ip);
        return 1;
    }
    if (dephy_wifi_scan_json(scan, sizeof(scan)) != 0 ||
        strstr(scan, "MQTT-BRIDGE-node1") == NULL) {
        fprintf(stderr, "unexpected scan: %s\n", scan);
        return 1;
    }
    printf("dephy_wifi smoke passed\n");
    return 0;
}

