#include <stdio.h>
#include <string.h>

#include "dephy_wifi/wifi.h"

#ifndef __ZEPHYR__

int dephy_wifi_start(const dephy_wifi_settings_t *settings,
                     char *ip_addr,
                     size_t ip_addr_cap)
{
    if (!settings || !ip_addr || ip_addr_cap == 0) {
        return -1;
    }
    snprintf(ip_addr, ip_addr_cap, "%s",
             settings->wifi_ssid[0] ?
             (settings->device_ip[0] ? settings->device_ip : "0.0.0.0") :
             (settings->device_ip[0] ? settings->device_ip : "192.168.4.1"));
    return 0;
}

int dephy_wifi_apply_settings(const dephy_wifi_settings_t *settings)
{
    char ip_addr[DEPHY_WIFI_HOST_MAX];

    return dephy_wifi_start(settings, ip_addr, sizeof(ip_addr));
}

int dephy_wifi_scan_json(char *buf, size_t buf_cap)
{
    if (!buf || buf_cap == 0) {
        return -1;
    }
    snprintf(buf, buf_cap,
             "[{\"ssid\":\"MQTT-BRIDGE-node1\",\"rssi\":-51,"
             "\"channel\":1,\"security\":\"wpa2\"}]");
    return 0;
}

#else

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#if defined(CONFIG_NET_DHCPV4)
#include <zephyr/net/dhcpv4.h>
#endif
#if defined(CONFIG_DEPHY_WIFI_SOFTAP) && defined(CONFIG_NET_DHCPV4_SERVER)
#include <zephyr/net/dhcpv4_server.h>
#endif
#include <zephyr/net/wifi_mgmt.h>
#if defined(CONFIG_WIFI_ESP32)
#include <esp_wifi.h>
#endif

LOG_MODULE_REGISTER(dephy_wifi, LOG_LEVEL_INF);

#define WIFI_CONNECT_TIMEOUT_S 30
#define WIFI_IP_TIMEOUT_S      15
#define WIFI_CONNECT_ATTEMPTS  3
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
#define AP_DEFAULT_CHANNEL      1
#endif
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
#define STA_RETRY_SECONDS       5
#define STA_ANNOUNCE_SECONDS    5
#endif
#if defined(CONFIG_DEPHY_WIFI_SCAN)
#define WIFI_SCAN_TIMEOUT_S     8
#define WIFI_SCAN_MAX_RESULTS   8
#endif

static K_SEM_DEFINE(sta_connected_sem, 0, 1);
static K_SEM_DEFINE(sta_ip_sem, 0, 1);
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
static K_SEM_DEFINE(ap_enabled_sem, 0, 1);
#endif
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static K_SEM_DEFINE(sta_reconfigure_sem, 0, 1);
#endif
#if defined(CONFIG_DEPHY_WIFI_SCAN)
static K_SEM_DEFINE(scan_done_sem, 0, 1);
#endif

static struct net_mgmt_event_callback wifi_cb;
static struct net_mgmt_event_callback ipv4_cb;
#if defined(CONFIG_DEPHY_WIFI_SCAN)
static struct net_mgmt_event_callback scan_cb;
#endif
static int callbacks_ready;

#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
static struct net_if *ap_iface;
#endif
static struct net_if *sta_iface;
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static struct k_mutex sta_settings_lock;
static dephy_wifi_settings_t sta_settings;
#endif
#if defined(CONFIG_DEPHY_WIFI_SCAN)
static struct k_mutex scan_lock;
#endif
static int sta_connect_status;
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static int sta_reconfigure_thread_ready;
#endif

#if defined(CONFIG_DEPHY_WIFI_SCAN)
typedef struct {
    char ssid[WIFI_SSID_MAX_LEN + 1];
    uint8_t channel;
    int8_t rssi;
    enum wifi_security_type security;
} dephy_wifi_scan_entry_t;

static dephy_wifi_scan_entry_t scan_entries[WIFI_SCAN_MAX_RESULTS];
static int scan_entry_count;
static int scan_status;
#endif

#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static void sta_reconfigure_thread(void *p1, void *p2, void *p3);
K_THREAD_STACK_DEFINE(sta_reconfigure_stack,
                      CONFIG_DEPHY_WIFI_RECONFIGURE_STACK_SIZE);
static struct k_thread sta_reconfigure_thread_data;
#endif

static void copy_ip(char *out, size_t cap, const char *fallback)
{
    struct net_in_addr *addr;

    if (!out || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (sta_iface) {
        addr = net_if_ipv4_get_global_addr(sta_iface, NET_ADDR_DHCP);
        if (!addr) {
            addr = net_if_ipv4_get_global_addr(sta_iface, NET_ADDR_MANUAL);
        }
        if (addr && net_addr_ntop(AF_INET, addr, out, cap)) {
            return;
        }
    }
    snprintf(out, cap, "%s", fallback ? fallback : "0.0.0.0");
}

static void disable_sta_power_save(void)
{
    struct wifi_ps_params ps = {
        .enabled = WIFI_PS_DISABLED,
    };
    int rc;

    rc = net_mgmt(NET_REQUEST_WIFI_PS, sta_iface, &ps, sizeof(ps));
    if (rc != 0) {
        LOG_WRN("STA power-save disable failed (%d)", rc);
    }

#if defined(CONFIG_WIFI_ESP32)
    rc = esp_wifi_set_ps(WIFI_PS_NONE);
    if (rc != 0) {
        LOG_WRN("ESP32 STA power-save disable failed (%d)", rc);
    } else {
        LOG_INF("ESP32 STA power-save disabled");
    }
#endif
}

#if defined(CONFIG_DEPHY_WIFI_SCAN)
static const char *security_name(enum wifi_security_type security)
{
    switch (security) {
    case WIFI_SECURITY_TYPE_NONE:
        return "open";
    case WIFI_SECURITY_TYPE_PSK:
        return "wpa2";
    case WIFI_SECURITY_TYPE_PSK_SHA256:
        return "wpa2-sha256";
    case WIFI_SECURITY_TYPE_SAE:
        return "wpa3";
    case WIFI_SECURITY_TYPE_EAP:
        return "enterprise";
    default:
        return "unknown";
    }
}

static int append_json_string(char *buf, size_t cap, int *pos,
                              const char *value)
{
    if (!buf || !pos || *pos < 0 || (size_t)*pos >= cap) {
        return -EINVAL;
    }

    buf[(*pos)++] = '"';
    while (*value && (size_t)*pos < cap - 2) {
        unsigned char c = (unsigned char)*value++;

        if (c == '"' || c == '\\') {
            if ((size_t)*pos >= cap - 3) {
                return -ENOSPC;
            }
            buf[(*pos)++] = '\\';
            buf[(*pos)++] = (char)c;
        } else if (c >= 0x20) {
            buf[(*pos)++] = (char)c;
        }
    }
    if ((size_t)*pos >= cap - 1) {
        return -ENOSPC;
    }
    buf[(*pos)++] = '"';
    buf[*pos] = '\0';
    return 0;
}

static void wifi_scan_event_handler(struct net_mgmt_event_callback *cb,
                                    uint64_t event,
                                    struct net_if *iface)
{
    ARG_UNUSED(iface);

    if (event == NET_EVENT_WIFI_SCAN_RESULT) {
        const struct wifi_scan_result *entry =
            (const struct wifi_scan_result *)cb->info;
        dephy_wifi_scan_entry_t *out;

        if (!entry || entry->ssid_length == 0 ||
            scan_entry_count >= WIFI_SCAN_MAX_RESULTS) {
            return;
        }

        out = &scan_entries[scan_entry_count++];
        memset(out, 0, sizeof(*out));
        memcpy(out->ssid, entry->ssid,
               MIN((size_t)entry->ssid_length, sizeof(out->ssid) - 1));
        out->channel = entry->channel;
        out->rssi = entry->rssi;
        out->security = entry->security;
        return;
    }

    if (event == NET_EVENT_WIFI_SCAN_DONE) {
        const struct wifi_status *status =
            (const struct wifi_status *)cb->info;

        scan_status = status ? status->status : 0;
        k_sem_give(&scan_done_sem);
    }
}
#endif

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
                               uint64_t event,
                               struct net_if *iface)
{
    ARG_UNUSED(iface);

    switch (event) {
    case NET_EVENT_WIFI_CONNECT_RESULT: {
        const struct wifi_status *st = (const struct wifi_status *)cb->info;
        if (st && st->status != 0) {
            sta_connect_status = -EIO;
            LOG_ERR("STA association failed (status=%d)", st->status);
            k_sem_give(&sta_connected_sem);
            return;
        }
        sta_connect_status = 0;
        LOG_INF("STA associated");
        k_sem_give(&sta_connected_sem);
        break;
    }
    case NET_EVENT_WIFI_DISCONNECT_RESULT:
        LOG_WRN("STA disconnected");
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
        if (sta_settings.wifi_ssid[0]) {
            k_sem_give(&sta_reconfigure_sem);
        }
#endif
        break;
    case NET_EVENT_WIFI_DISCONNECT_COMPLETE: {
        const struct wifi_status *st = (const struct wifi_status *)cb->info;
        LOG_WRN("STA disconnect complete status=%d", st ? st->status : 0);
        break;
    }
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
    case NET_EVENT_WIFI_AP_ENABLE_RESULT:
        LOG_INF("SoftAP enabled");
        k_sem_give(&ap_enabled_sem);
        break;
    case NET_EVENT_WIFI_AP_DISABLE_RESULT:
        LOG_INF("SoftAP disabled");
        break;
    case NET_EVENT_WIFI_AP_STA_CONNECTED: {
        const struct wifi_ap_sta_info *sta = (const struct wifi_ap_sta_info *)cb->info;
        if (sta) {
            LOG_INF("SoftAP station joined: %02x:%02x:%02x:%02x:%02x:%02x",
                    sta->mac[0], sta->mac[1], sta->mac[2],
                    sta->mac[3], sta->mac[4], sta->mac[5]);
        }
        break;
    }
    case NET_EVENT_WIFI_AP_STA_DISCONNECTED:
        LOG_INF("SoftAP station left");
        break;
#endif
    default:
        break;
    }
}

static void ipv4_event_handler(struct net_mgmt_event_callback *cb,
                               uint64_t event,
                               struct net_if *iface)
{
    ARG_UNUSED(cb);

    if (event == NET_EVENT_IPV4_ADDR_ADD && iface == sta_iface) {
        LOG_INF("STA IPv4 address obtained");
        k_sem_give(&sta_ip_sem);
    }
}

static void ensure_callbacks(void)
{
    if (callbacks_ready) {
        return;
    }

#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
    k_mutex_init(&sta_settings_lock);
#endif
#if defined(CONFIG_DEPHY_WIFI_SCAN)
    k_mutex_init(&scan_lock);
#endif

    net_mgmt_init_event_callback(&wifi_cb, wifi_event_handler,
                                 NET_EVENT_WIFI_CONNECT_RESULT |
                                 NET_EVENT_WIFI_DISCONNECT_RESULT |
                                 NET_EVENT_WIFI_DISCONNECT_COMPLETE
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
                                 | NET_EVENT_WIFI_AP_ENABLE_RESULT
                                 | NET_EVENT_WIFI_AP_DISABLE_RESULT
                                 | NET_EVENT_WIFI_AP_STA_CONNECTED
                                 | NET_EVENT_WIFI_AP_STA_DISCONNECTED
#endif
                                 );
    net_mgmt_add_event_callback(&wifi_cb);

    net_mgmt_init_event_callback(&ipv4_cb, ipv4_event_handler,
                                 NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&ipv4_cb);

#if defined(CONFIG_DEPHY_WIFI_SCAN)
    net_mgmt_init_event_callback(&scan_cb, wifi_scan_event_handler,
                                 NET_EVENT_WIFI_SCAN_RESULT |
                                 NET_EVENT_WIFI_SCAN_DONE);
#endif
    callbacks_ready = 1;
}

static void ensure_wifi_interfaces(void)
{
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
    ap_iface = net_if_get_wifi_sap();
#endif
    sta_iface = net_if_get_wifi_sta();
#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
    if (!ap_iface) {
        ap_iface = net_if_get_default();
    }
#endif
    if (!sta_iface) {
        sta_iface = net_if_get_default();
    }
}

#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static void ensure_sta_reconfigure_thread(void)
{
    if (sta_reconfigure_thread_ready) {
        return;
    }

    k_thread_create(&sta_reconfigure_thread_data,
                    sta_reconfigure_stack,
                    K_THREAD_STACK_SIZEOF(sta_reconfigure_stack),
                    sta_reconfigure_thread,
                    NULL, NULL, NULL,
                    8, 0, K_NO_WAIT);
    k_thread_name_set(&sta_reconfigure_thread_data, "wifi_sta_cfg");
    sta_reconfigure_thread_ready = 1;
}
#endif

#if defined(CONFIG_DEPHY_WIFI_SOFTAP)
static int configure_ap_ipv4(const dephy_wifi_settings_t *settings)
{
    struct net_in_addr addr;
    struct net_in_addr netmask;
    const char *ip = settings->device_ip[0] ?
        settings->device_ip : "192.168.4.1";
    const char *mask = settings->netmask[0] ?
        settings->netmask : "255.255.255.0";

    if (net_addr_pton(AF_INET, ip, &addr) != 0 ||
        net_addr_pton(AF_INET, mask, &netmask) != 0) {
        LOG_ERR("invalid AP IPv4 settings ip=%s mask=%s", ip, mask);
        return -EINVAL;
    }

    net_if_ipv4_set_gw(ap_iface, &addr);
    if (!net_if_ipv4_addr_lookup(&addr, NULL)) {
        if (!net_if_ipv4_addr_add(ap_iface, &addr, NET_ADDR_MANUAL, 0)) {
            LOG_ERR("failed to assign SoftAP IPv4 %s", ip);
            return -EIO;
        }
    }
    if (!net_if_ipv4_set_netmask_by_addr(ap_iface, &addr, &netmask)) {
        LOG_ERR("failed to set SoftAP netmask %s", mask);
        return -EIO;
    }

#if defined(CONFIG_NET_DHCPV4_SERVER)
    struct net_in_addr pool_start;

    pool_start = addr;
    pool_start.s4_addr[3] = (uint8_t)(pool_start.s4_addr[3] + 10);
    if (net_dhcpv4_server_start(ap_iface, &pool_start) != 0) {
        LOG_WRN("DHCPv4 server start failed or already running");
    } else {
        LOG_INF("SoftAP DHCPv4 server started at %s", ip);
    }
#else
    LOG_INF("SoftAP DHCPv4 server disabled by build config");
#endif
    return 0;
}

static int start_ap(const dephy_wifi_settings_t *settings)
{
    struct wifi_connect_req_params params;
    int rc;

    if (!settings->ap_ssid[0]) {
        return 0;
    }
    if (!ap_iface) {
        LOG_ERR("no Wi-Fi SoftAP interface");
        return -ENODEV;
    }

    rc = configure_ap_ipv4(settings);
    if (rc != 0) {
        return rc;
    }

    memset(&params, 0, sizeof(params));
    params.ssid = (const uint8_t *)settings->ap_ssid;
    params.ssid_length = (uint8_t)strlen(settings->ap_ssid);
    params.psk = (const uint8_t *)settings->ap_password;
    params.psk_length = (uint8_t)strlen(settings->ap_password);
    params.channel = AP_DEFAULT_CHANNEL;
    params.band = WIFI_FREQ_BAND_2_4_GHZ;
    params.security = params.psk_length > 0 ?
        WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;

    k_sem_reset(&ap_enabled_sem);
    LOG_INF("Starting SoftAP ssid=%s ip=%s",
            settings->ap_ssid,
            settings->device_ip[0] ? settings->device_ip : "192.168.4.1");
    rc = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, ap_iface, &params, sizeof(params));
    if (rc != 0) {
        LOG_ERR("SoftAP enable failed (%d)", rc);
        return rc;
    }
    if (k_sem_take(&ap_enabled_sem, K_SECONDS(10)) != 0) {
        LOG_WRN("SoftAP enable event timeout; continuing after request success");
    }
    return 0;
}
#else
static int start_ap(const dephy_wifi_settings_t *settings)
{
    if (settings->ap_ssid[0]) {
        LOG_ERR("SoftAP support disabled by build config");
        return -ENOTSUP;
    }
    return 0;
}
#endif

static int configure_sta_ipv4(const dephy_wifi_settings_t *settings,
                              char *ip_addr,
                              size_t ip_addr_cap)
{
    struct net_in_addr addr;
    struct net_in_addr gw;
    struct net_in_addr netmask;
    const char *ip = settings->device_ip[0] ?
        settings->device_ip : "0.0.0.0";
    const char *gateway = settings->gateway[0] ?
        settings->gateway : "0.0.0.0";
    const char *mask = settings->netmask[0] ?
        settings->netmask : "255.255.255.0";

    if (net_addr_pton(AF_INET, ip, &addr) != 0 ||
        net_addr_pton(AF_INET, gateway, &gw) != 0 ||
        net_addr_pton(AF_INET, mask, &netmask) != 0) {
        LOG_ERR("invalid STA IPv4 settings ip=%s gw=%s mask=%s",
                ip, gateway, mask);
        return -EINVAL;
    }

    if (strcmp(ip, "0.0.0.0") == 0) {
        LOG_ERR("static STA IPv4 requires a non-zero device_ip");
        return -EINVAL;
    }

#if defined(CONFIG_NET_DHCPV4)
    (void)net_dhcpv4_stop(sta_iface);
#endif
    net_if_ipv4_set_gw(sta_iface, &gw);
    if (!net_if_ipv4_addr_lookup(&addr, NULL)) {
        if (!net_if_ipv4_addr_add(sta_iface, &addr, NET_ADDR_MANUAL, 0)) {
            LOG_ERR("failed to assign STA IPv4 %s", ip);
            return -EIO;
        }
    }
    if (!net_if_ipv4_set_netmask_by_addr(sta_iface, &addr, &netmask)) {
        LOG_ERR("failed to set STA netmask %s", mask);
        return -EIO;
    }

    copy_ip(ip_addr, ip_addr_cap, ip);
    LOG_INF("STA static IPv4 %s gw=%s", ip_addr, gateway);
    return 0;
}

static void announce_sta_ipv4(const dephy_wifi_settings_t *settings)
{
    struct sockaddr_in dst;
    const char payload = 0;
    int fd;

    if (!settings->gateway[0] ||
        strcmp(settings->gateway, "0.0.0.0") == 0) {
        return;
    }

    fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        LOG_WRN("STA IPv4 announce socket failed (%d)", errno);
        return;
    }

    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = 200000,
    };
    (void)zsock_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);
    if (net_addr_pton(AF_INET, settings->gateway, &dst.sin_addr) != 0) {
        LOG_WRN("STA IPv4 announce invalid gateway %s", settings->gateway);
        (void)zsock_close(fd);
        return;
    }

    if (zsock_sendto(fd, &payload, sizeof(payload), 0,
                     (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        LOG_WRN("STA IPv4 announce send failed (%d)", errno);
    } else {
        LOG_INF("STA IPv4 announced to gateway %s", settings->gateway);
    }
    (void)zsock_close(fd);
}

static int start_sta(const dephy_wifi_settings_t *settings,
                     char *ip_addr,
                     size_t ip_addr_cap)
{
    struct wifi_connect_req_params params;
    int rc;

    if (!settings->wifi_ssid[0]) {
        copy_ip(ip_addr, ip_addr_cap,
                settings->device_ip[0] ? settings->device_ip : "192.168.4.1");
        return 0;
    }
    if (!sta_iface) {
        LOG_ERR("no Wi-Fi STA interface");
        return -ENODEV;
    }

    memset(&params, 0, sizeof(params));
    params.ssid = (const uint8_t *)settings->wifi_ssid;
    params.ssid_length = (uint8_t)strlen(settings->wifi_ssid);
    params.psk = (const uint8_t *)settings->wifi_password;
    params.psk_length = (uint8_t)strlen(settings->wifi_password);
    params.channel = WIFI_CHANNEL_ANY;
    params.band = WIFI_FREQ_BAND_2_4_GHZ;
    params.security = params.psk_length > 0 ?
        WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;
    params.mfp = WIFI_MFP_OPTIONAL;
    params.timeout = SYS_FOREVER_MS;

    if (!settings->dhcp_enabled) {
        rc = configure_sta_ipv4(settings, ip_addr, ip_addr_cap);
        if (rc != 0) {
            return rc;
        }
    }

    for (int attempt = 1; attempt <= WIFI_CONNECT_ATTEMPTS; attempt++) {
        k_sem_reset(&sta_connected_sem);
        k_sem_reset(&sta_ip_sem);
        sta_connect_status = -EINPROGRESS;
        LOG_INF("Connecting STA to ssid=%s attempt=%d/%d",
                settings->wifi_ssid, attempt, WIFI_CONNECT_ATTEMPTS);
        (void)net_mgmt(NET_REQUEST_WIFI_DISCONNECT, sta_iface, NULL, 0);
        k_sleep(K_MSEC(250));
        rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &params, sizeof(params));
        if (rc != 0) {
            LOG_ERR("STA connect request failed (%d)", rc);
        } else if (k_sem_take(&sta_connected_sem,
                              K_SECONDS(WIFI_CONNECT_TIMEOUT_S)) != 0) {
            LOG_ERR("STA association timeout");
            rc = -ETIMEDOUT;
        } else if (sta_connect_status != 0) {
            rc = sta_connect_status;
        } else {
            rc = 0;
            break;
        }

        if (attempt < WIFI_CONNECT_ATTEMPTS) {
            LOG_WRN("STA association retry in 2s (%d)", rc);
            (void)net_mgmt(NET_REQUEST_WIFI_DISCONNECT, sta_iface, NULL, 0);
            k_sleep(K_SECONDS(2));
        }
    }
    if (rc != 0) {
        return rc;
    }

    disable_sta_power_save();

    if (!settings->dhcp_enabled) {
        announce_sta_ipv4(settings);
    }

    if (settings->dhcp_enabled) {
#if defined(CONFIG_NET_DHCPV4)
        net_dhcpv4_start(sta_iface);
        if (k_sem_take(&sta_ip_sem, K_SECONDS(WIFI_IP_TIMEOUT_S)) != 0) {
            LOG_ERR("STA DHCP timeout");
            return -ETIMEDOUT;
        }
        copy_ip(ip_addr, ip_addr_cap, "0.0.0.0");
        if (strcmp(ip_addr, "0.0.0.0") == 0 &&
            settings->device_ip[0] &&
            strcmp(settings->device_ip, "0.0.0.0") != 0) {
            snprintf(ip_addr, ip_addr_cap, "%s", settings->device_ip);
        }
        LOG_INF("STA IPv4 %s", ip_addr);
        return 0;
#else
        LOG_ERR("STA DHCP requested but CONFIG_NET_DHCPV4 is disabled");
        return -ENOTSUP;
#endif
    }

    return 0;
}

#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
static void sta_reconfigure_thread(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (1) {
        dephy_wifi_settings_t settings;

        if (k_sem_take(&sta_reconfigure_sem,
                       K_SECONDS(STA_ANNOUNCE_SECONDS)) != 0) {
            k_mutex_lock(&sta_settings_lock, K_FOREVER);
            settings = sta_settings;
            k_mutex_unlock(&sta_settings_lock);

            if (settings.wifi_ssid[0] && !settings.dhcp_enabled) {
                announce_sta_ipv4(&settings);
            }
            continue;
        }

        while (1) {
            char ip_addr[DEPHY_WIFI_HOST_MAX];
            int rc;

            k_mutex_lock(&sta_settings_lock, K_FOREVER);
            settings = sta_settings;
            k_mutex_unlock(&sta_settings_lock);

            if (!settings.wifi_ssid[0]) {
                break;
            }

            rc = start_sta(&settings, ip_addr, sizeof(ip_addr));
            if (rc == 0) {
                LOG_INF("STA reconfigure complete ip=%s", ip_addr);
                break;
            }

            LOG_WRN("STA reconfigure retry in %ds (%d)",
                    STA_RETRY_SECONDS, rc);
            k_sleep(K_SECONDS(STA_RETRY_SECONDS));
        }
    }
}
#endif

int dephy_wifi_apply_settings(const dephy_wifi_settings_t *settings)
{
    if (!settings) {
        return -EINVAL;
    }

#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
    ensure_callbacks();
    ensure_wifi_interfaces();
    ensure_sta_reconfigure_thread();

    k_mutex_lock(&sta_settings_lock, K_FOREVER);
    sta_settings = *settings;
    k_mutex_unlock(&sta_settings_lock);
    k_sem_give(&sta_reconfigure_sem);
    return 0;
#else
    char ip_addr[DEPHY_WIFI_HOST_MAX];

    return dephy_wifi_start(settings, ip_addr, sizeof(ip_addr));
#endif
}

#if defined(CONFIG_DEPHY_WIFI_SCAN)
int dephy_wifi_scan_json(char *buf, size_t buf_cap)
{
    struct wifi_scan_params params;
    int rc;
    int pos = 0;

    if (!buf || buf_cap < 3) {
        return -EINVAL;
    }

    ensure_callbacks();
    ensure_wifi_interfaces();
    if (!sta_iface) {
        return -ENODEV;
    }

    rc = k_mutex_lock(&scan_lock, K_SECONDS(WIFI_SCAN_TIMEOUT_S));
    if (rc != 0) {
        return rc;
    }

    memset(scan_entries, 0, sizeof(scan_entries));
    scan_entry_count = 0;
    scan_status = 0;
    k_sem_reset(&scan_done_sem);

    memset(&params, 0, sizeof(params));
    params.scan_type = WIFI_SCAN_TYPE_PASSIVE;
    params.bands = BIT(WIFI_FREQ_BAND_2_4_GHZ);
    params.dwell_time_passive = 120;
    params.max_bss_cnt = WIFI_SCAN_MAX_RESULTS;

    LOG_INF("WiFi scan requested");
    net_mgmt_add_event_callback(&scan_cb);
    rc = net_mgmt(NET_REQUEST_WIFI_SCAN, sta_iface, &params, sizeof(params));
    if (rc != 0) {
        LOG_ERR("WiFi scan request failed (%d)", rc);
        net_mgmt_del_event_callback(&scan_cb);
        k_mutex_unlock(&scan_lock);
        return rc;
    }

    rc = k_sem_take(&scan_done_sem, K_SECONDS(WIFI_SCAN_TIMEOUT_S));
    net_mgmt_del_event_callback(&scan_cb);
    if (rc != 0) {
        LOG_ERR("WiFi scan timed out");
        k_mutex_unlock(&scan_lock);
        return -ETIMEDOUT;
    }
    if (scan_status != 0) {
        rc = scan_status;
        LOG_ERR("WiFi scan completed with status %d", rc);
        k_mutex_unlock(&scan_lock);
        return rc;
    }
    LOG_INF("WiFi scan completed with %d result(s)", scan_entry_count);

    buf[pos++] = '[';
    for (int i = 0; i < scan_entry_count; i++) {
        int written;

        if (i > 0) {
            if ((size_t)pos >= buf_cap - 1) {
                k_mutex_unlock(&scan_lock);
                return -ENOSPC;
            }
            buf[pos++] = ',';
        }

        written = snprintf(buf + pos, buf_cap - (size_t)pos,
                           "{\"ssid\":");
        if (written < 0 || written >= (int)(buf_cap - (size_t)pos)) {
            k_mutex_unlock(&scan_lock);
            return -ENOSPC;
        }
        pos += written;
        if (append_json_string(buf, buf_cap, &pos, scan_entries[i].ssid) != 0) {
            k_mutex_unlock(&scan_lock);
            return -ENOSPC;
        }
        written = snprintf(buf + pos, buf_cap - (size_t)pos,
                           ",\"rssi\":%d,\"channel\":%u,\"security\":",
                           scan_entries[i].rssi, scan_entries[i].channel);
        if (written < 0 || written >= (int)(buf_cap - (size_t)pos)) {
            k_mutex_unlock(&scan_lock);
            return -ENOSPC;
        }
        pos += written;
        if (append_json_string(buf, buf_cap, &pos,
                               security_name(scan_entries[i].security)) != 0) {
            k_mutex_unlock(&scan_lock);
            return -ENOSPC;
        }
        if ((size_t)pos >= buf_cap - 2) {
            k_mutex_unlock(&scan_lock);
            return -ENOSPC;
        }
        buf[pos++] = '}';
        buf[pos] = '\0';
    }

    if ((size_t)pos >= buf_cap - 2) {
        k_mutex_unlock(&scan_lock);
        return -ENOSPC;
    }
    buf[pos++] = ']';
    buf[pos] = '\0';

    k_mutex_unlock(&scan_lock);
    return 0;
}
#else
int dephy_wifi_scan_json(char *buf, size_t buf_cap)
{
    if (buf && buf_cap > 0) {
        buf[0] = '\0';
    }
    return -ENOTSUP;
}
#endif

int dephy_wifi_start(const dephy_wifi_settings_t *settings,
                     char *ip_addr,
                     size_t ip_addr_cap)
{
    int rc;

    if (!settings || !ip_addr || ip_addr_cap == 0) {
        return -EINVAL;
    }
    ip_addr[0] = '\0';

    ensure_callbacks();
    ensure_wifi_interfaces();

    rc = start_ap(settings);
    if (rc != 0) {
        return rc;
    }

    if (settings->wifi_ssid[0]) {
#if defined(CONFIG_DEPHY_WIFI_RECONFIGURE)
        ensure_sta_reconfigure_thread();

        k_mutex_lock(&sta_settings_lock, K_FOREVER);
        sta_settings = *settings;
        k_mutex_unlock(&sta_settings_lock);
#endif

        return start_sta(settings, ip_addr, ip_addr_cap);
    }

    copy_ip(ip_addr, ip_addr_cap,
            settings->device_ip[0] ? settings->device_ip : "192.168.4.1");
    return 0;
}

#endif
