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
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/dhcpv4_server.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(dephy_wifi, LOG_LEVEL_INF);

#define WIFI_CONNECT_TIMEOUT_S 10
#define WIFI_IP_TIMEOUT_S      15
#define AP_DEFAULT_CHANNEL      1
#define STA_RETRY_SECONDS       5
#define WIFI_SCAN_TIMEOUT_S     8
#define WIFI_SCAN_MAX_RESULTS  12

static K_SEM_DEFINE(sta_connected_sem, 0, 1);
static K_SEM_DEFINE(sta_ip_sem, 0, 1);
static K_SEM_DEFINE(ap_enabled_sem, 0, 1);
static K_SEM_DEFINE(sta_reconfigure_sem, 0, 1);
static K_SEM_DEFINE(scan_done_sem, 0, 1);

static struct net_mgmt_event_callback wifi_cb;
static struct net_mgmt_event_callback ipv4_cb;
static struct net_mgmt_event_callback scan_cb;
static int callbacks_ready;

static struct net_if *ap_iface;
static struct net_if *sta_iface;
static struct k_mutex sta_settings_lock;
static struct k_mutex scan_lock;
static dephy_wifi_settings_t sta_settings;
static int sta_reconfigure_thread_ready;

typedef struct {
    char ssid[WIFI_SSID_MAX_LEN + 1];
    uint8_t channel;
    int8_t rssi;
    enum wifi_security_type security;
} dephy_wifi_scan_entry_t;

static dephy_wifi_scan_entry_t scan_entries[WIFI_SCAN_MAX_RESULTS];
static int scan_entry_count;
static int scan_status;

static void sta_reconfigure_thread(void *p1, void *p2, void *p3);
K_THREAD_STACK_DEFINE(sta_reconfigure_stack, 4096);
static struct k_thread sta_reconfigure_thread_data;

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

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
                               uint64_t event,
                               struct net_if *iface)
{
    ARG_UNUSED(iface);

    switch (event) {
    case NET_EVENT_WIFI_CONNECT_RESULT: {
        const struct wifi_status *st = (const struct wifi_status *)cb->info;
        if (st && st->status != 0) {
            LOG_ERR("STA association failed (status=%d)", st->status);
            return;
        }
        LOG_INF("STA associated");
        k_sem_give(&sta_connected_sem);
        break;
    }
    case NET_EVENT_WIFI_DISCONNECT_RESULT:
        LOG_WRN("STA disconnected");
        if (sta_settings.wifi_ssid[0]) {
            k_sem_give(&sta_reconfigure_sem);
        }
        break;
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

    k_mutex_init(&sta_settings_lock);
    k_mutex_init(&scan_lock);

    net_mgmt_init_event_callback(&wifi_cb, wifi_event_handler,
                                 NET_EVENT_WIFI_CONNECT_RESULT |
                                 NET_EVENT_WIFI_DISCONNECT_RESULT |
                                 NET_EVENT_WIFI_AP_ENABLE_RESULT |
                                 NET_EVENT_WIFI_AP_DISABLE_RESULT |
                                 NET_EVENT_WIFI_AP_STA_CONNECTED |
                                 NET_EVENT_WIFI_AP_STA_DISCONNECTED);
    net_mgmt_add_event_callback(&wifi_cb);

    net_mgmt_init_event_callback(&ipv4_cb, ipv4_event_handler,
                                 NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&ipv4_cb);

    net_mgmt_init_event_callback(&scan_cb, wifi_scan_event_handler,
                                 NET_EVENT_WIFI_SCAN_RESULT |
                                 NET_EVENT_WIFI_SCAN_DONE);
    callbacks_ready = 1;
}

static void ensure_wifi_interfaces(void)
{
    ap_iface = net_if_get_wifi_sap();
    sta_iface = net_if_get_wifi_sta();
    if (!ap_iface) {
        ap_iface = net_if_get_default();
    }
    if (!sta_iface) {
        sta_iface = net_if_get_default();
    }
}

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

static int configure_ap_ipv4(const dephy_wifi_settings_t *settings)
{
    struct net_in_addr addr;
    struct net_in_addr netmask;
    struct net_in_addr pool_start;
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

    pool_start = addr;
    pool_start.s4_addr[3] = (uint8_t)(pool_start.s4_addr[3] + 10);
    if (net_dhcpv4_server_start(ap_iface, &pool_start) != 0) {
        LOG_WRN("DHCPv4 server start failed or already running");
    } else {
        LOG_INF("SoftAP DHCPv4 server started at %s", ip);
    }
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

    k_sem_reset(&sta_connected_sem);
    k_sem_reset(&sta_ip_sem);
    LOG_INF("Connecting STA to ssid=%s", settings->wifi_ssid);
    (void)net_mgmt(NET_REQUEST_WIFI_DISCONNECT, sta_iface, NULL, 0);
    k_sleep(K_MSEC(150));
    rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &params, sizeof(params));
    if (rc != 0) {
        LOG_ERR("STA connect request failed (%d)", rc);
        return rc;
    }
    if (k_sem_take(&sta_connected_sem, K_SECONDS(WIFI_CONNECT_TIMEOUT_S)) != 0) {
        LOG_ERR("STA association timeout");
        return -ETIMEDOUT;
    }

    if (settings->dhcp_enabled) {
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
    }

    copy_ip(ip_addr, ip_addr_cap,
            settings->device_ip[0] ? settings->device_ip : "0.0.0.0");
    return 0;
}

static void sta_reconfigure_thread(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (1) {
        dephy_wifi_settings_t settings;

        k_sem_take(&sta_reconfigure_sem, K_FOREVER);

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

int dephy_wifi_apply_settings(const dephy_wifi_settings_t *settings)
{
    if (!settings) {
        return -EINVAL;
    }

    ensure_callbacks();
    ensure_wifi_interfaces();
    ensure_sta_reconfigure_thread();

    k_mutex_lock(&sta_settings_lock, K_FOREVER);
    sta_settings = *settings;
    k_mutex_unlock(&sta_settings_lock);
    k_sem_give(&sta_reconfigure_sem);
    return 0;
}

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
    params.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    params.bands = BIT(WIFI_FREQ_BAND_2_4_GHZ);
    params.dwell_time_active = 20;
    params.dwell_time_passive = 40;
    params.max_bss_cnt = WIFI_SCAN_MAX_RESULTS;

    net_mgmt_add_event_callback(&scan_cb);
    rc = net_mgmt(NET_REQUEST_WIFI_SCAN, sta_iface, &params, sizeof(params));
    if (rc != 0) {
        net_mgmt_del_event_callback(&scan_cb);
        k_mutex_unlock(&scan_lock);
        return rc;
    }

    rc = k_sem_take(&scan_done_sem, K_SECONDS(WIFI_SCAN_TIMEOUT_S));
    net_mgmt_del_event_callback(&scan_cb);
    if (rc != 0) {
        k_mutex_unlock(&scan_lock);
        return -ETIMEDOUT;
    }
    if (scan_status != 0) {
        rc = scan_status;
        k_mutex_unlock(&scan_lock);
        return rc;
    }

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
        (void)dephy_wifi_apply_settings(settings);
        copy_ip(ip_addr, ip_addr_cap,
                settings->device_ip[0] ? settings->device_ip : "192.168.4.1");
        return 0;
    }

    copy_ip(ip_addr, ip_addr_cap,
            settings->device_ip[0] ? settings->device_ip : "192.168.4.1");
    return 0;
}

#endif

