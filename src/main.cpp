/*
 * ESP-IDF WiFi Repeater with NAPT (Network Address Port Translation)
 * Based on official ESP-IDF softap_sta example
 *
 * This creates a WiFi repeater that:
 * - Connects to an upstream WiFi network (Station mode)
 * - Provides an Access Point for clients
 * - Routes traffic between them using NAPT
 * - Optionally tunnels all client traffic through WireGuard
 * - Detects captive portals on the uplink network and sends the clients'
 *   connectivity checks to the login page (DNS proxy)
 * - Acts as a captive portal itself while in setup mode
 */

#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/lwip_napt.h"
#include "lwip/sockets.h"
#include "lwip/ip4_addr.h"
#include "lwip/prot/ip.h"
#include "dhcpserver/dhcpserver.h"
#include "esp_netif_sntp.h"
#include "esp_http_client.h"
#include "esp_app_desc.h"
#include "esp_random.h"
#include "esp_pm.h"
#include "lwip/netdb.h"

// Firmware version (git describe), written by scripts/build_version.py
#if __has_include("firmware_version.h")
#include "firmware_version.h"
#endif
#include "esp_timer.h"
#include "mbedtls/base64.h"

// WireGuard
#include "esp_wireguard.h"
#include "wireguard.h" // peer state for the debug page (library pinned in platformio.ini)

// Battery (ADC) includes
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"

// Display includes
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"

// Web server includes
#include "esp_http_server.h"

/* WiFi Configuration - Dynamic (loaded from NVS) */
#define WIFI_STA_DRIVER_RETRIES 10  // retries within one connection attempt
#define WIFI_RECONNECT_MIN_MS 1000   // first reconnect delay after losing the uplink
#define WIFI_RECONNECT_MAX_MS 60000  // the delay doubles up to this
#define WIFI_AP_CHANNEL 1
#define WIFI_AP_MAX_CONNECTIONS 10

/* ═══════════════════════════════════════════════════════════════════
 * DEFAULT CONFIGURATION (for initial setup via web interface)
 * ═══════════════════════════════════════════════════════════════════ */
#define DEFAULT_CONFIG_AP_SSID "CardRepeater" // AP name for config mode
#define DEFAULT_CONFIG_AP_PASSWORD ""         // Open AP for easy access
#define WEB_CONFIG_IP "192.168.4.1"           // IP address for web config
/* ═══════════════════════════════════════════════════════════════════ */

/* NVS Configuration Keys */
#define NVS_NAMESPACE "wifi_config"
#define NVS_KEY_CONFIGURED "configured"
#define NVS_KEY_STA_SSID "sta_ssid"
#define NVS_KEY_STA_PASS "sta_pass"
#define NVS_KEY_AP_SSID "ap_ssid"
#define NVS_KEY_AP_PASS "ap_pass"
#define NVS_KEY_WG_ENABLED "wg_en"
#define NVS_KEY_WG_PRIVATE_KEY "wg_priv"
#define NVS_KEY_WG_ADDRESS "wg_addr"
#define NVS_KEY_WG_PEER_KEY "wg_peer"
#define NVS_KEY_WG_PSK "wg_psk"
#define NVS_KEY_WG_ENDPOINT "wg_host"
#define NVS_KEY_WG_PORT "wg_port"
#define NVS_KEY_WG_KEEPALIVE "wg_ka"
#define NVS_KEY_WG_DNS "wg_dns"
#define NVS_KEY_ADMIN_PASS "admin_pass"
#define NVS_KEY_DISPLAY_TIMEOUT "disp_off"
#define NVS_KEY_PORTAL_REDIRECT "portal_redir"
#define NVS_KEY_TX_POWER "tx_pwr"
#define NVS_KEY_ECO_MODE "eco"
#define NVS_KEY_WG_KILL_SWITCH "wg_kill"

/* WireGuard defaults */
#define WG_DEFAULT_PORT 51820
#define WG_DEFAULT_KEEPALIVE 25
#define WG_KEY_B64_LEN 44 // base64 of a 32 byte key

/* Device defaults */
#define DEFAULT_DISPLAY_TIMEOUT 60 // seconds until the screen turns off, 0 = always on
#define ADMIN_PASSWORD_MIN_LEN 8

/* Configuration storage */
typedef struct
{
  char sta_ssid[32];
  char sta_password[64];
  char extra_ssid[4][32]; // more uplink networks, the strongest one in range is used
  char extra_password[4][64];
  char ap_ssid[32];
  char ap_password[64];
  bool configured;

  /* WireGuard (optional) */
  bool wg_enabled;
  char wg_private_key[WG_KEY_B64_LEN + 1];
  char wg_address[20]; // CIDR, e.g. 10.6.0.2/32
  char wg_peer_public_key[WG_KEY_B64_LEN + 1];
  char wg_preshared_key[WG_KEY_B64_LEN + 1];
  char wg_endpoint[64];
  uint16_t wg_port;
  uint16_t wg_keepalive;
  char wg_dns[16]; // DNS offered to AP clients when VPN is enabled (empty = upstream)
  bool wg_kill_switch; // block client traffic while the tunnel is down

  /* Device */
  char admin_password[64];  // web panel login (empty only in configs from older firmware)
  uint16_t display_timeout; // seconds until the screen turns off, 0 = always on
  bool portal_redirect;     // send clients' connectivity checks to the uplink's login page
  uint8_t tx_power;         // max WiFi transmit power in dBm, 0 = maximum
  bool eco_mode;            // CPU 80-160 MHz instead of 240 MHz
} repeater_config_t;

static repeater_config_t stored_config = {0};

/* Saved uplink networks: 0 = main network, 1-4 = extra networks */
#define UPLINK_NETWORKS 5
static int active_network = 0; // the one being connected / connected to

static const char *network_ssid(int i)
{
  return i == 0 ? stored_config.sta_ssid : stored_config.extra_ssid[i - 1];
}

static const char *network_password(int i)
{
  return i == 0 ? stored_config.sta_password : stored_config.extra_password[i - 1];
}

static int saved_network_count(void)
{
  int count = 0;
  for (int i = 0; i < UPLINK_NETWORKS; i++)
    if (network_ssid(i)[0] != '\0')
      count++;
  return count;
}

/* FreeRTOS event group to signal when we are connected */
#define WIFI_CONNECTED_BIT BIT0

/* DHCP server option */
#define DHCPS_OFFER_DNS 0x02

/* Logging tags */
static const char *TAG_AP = "WiFi AP";
static const char *TAG_STA = "WiFi STA";
static const char *TAG_MAIN = "WiFi Repeater";

static EventGroupHandle_t s_wifi_event_group;

/* Uplink reconnects with exponential backoff (never gives up) */
static esp_timer_handle_t reconnect_timer = NULL;
static uint32_t reconnect_delay_ms = WIFI_RECONNECT_MIN_MS;
static volatile bool scan_in_progress = false;
static bool sta_open_fallback = false; // password saved, but the uplink turned out to be an open network

/* Uplink diagnostics (debug page, display) */
static uint8_t last_disconnect_reason = 0; // 0 = none yet
static int64_t last_disconnect_us = 0;
static uint32_t disconnect_count = 0;
static int64_t connected_since_us = 0;

/* Recent log output, kept for the debug page (also goes to the serial port) */
#define DEBUG_LOG_SIZE 6144
static char debug_log[DEBUG_LOG_SIZE];
static size_t debug_log_head = 0; // next write position
static bool debug_log_wrapped = false;
static portMUX_TYPE debug_log_lock = portMUX_INITIALIZER_UNLOCKED;
static vprintf_like_t serial_vprintf = NULL;

static int debug_log_vprintf(const char *fmt, va_list args)
{
  char line[160];
  va_list copy;
  va_copy(copy, args);
  int len = vsnprintf(line, sizeof(line), fmt, copy);
  va_end(copy);
  if (len > (int)sizeof(line) - 1)
    len = sizeof(line) - 1;

  if (len > 0)
  {
    taskENTER_CRITICAL(&debug_log_lock);
    bool in_escape = false; // drop ANSI color codes
    for (int i = 0; i < len; i++)
    {
      char c = line[i];
      if (c == '\033')
        in_escape = true;
      if (in_escape)
      {
        if (c == 'm')
          in_escape = false;
        continue;
      }
      debug_log[debug_log_head++] = c;
      if (debug_log_head == DEBUG_LOG_SIZE)
      {
        debug_log_head = 0;
        debug_log_wrapped = true;
      }
    }
    taskEXIT_CRITICAL(&debug_log_lock);
  }
  return serial_vprintf ? serial_vprintf(fmt, args) : vprintf(fmt, args);
}

/* Short explanation of a WiFi disconnect reason (fits the display) */
static const char *disconnect_reason_text(uint8_t reason)
{
  switch (reason)
  {
  case 0:
    return "connecting";
  case WIFI_REASON_NO_AP_FOUND:
    return "network not found";
  case WIFI_REASON_AUTH_FAIL:
  case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
  case WIFI_REASON_HANDSHAKE_TIMEOUT:
    return "wrong password?";
  case WIFI_REASON_ASSOC_FAIL:
  case WIFI_REASON_CONNECTION_FAIL:
    return "AP refused connection";
  case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    return "security not supported";
  case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    return "security below WPA2";
  case WIFI_REASON_BEACON_TIMEOUT:
    return "signal lost";
  case WIFI_REASON_ASSOC_LEAVE:
    return "disconnected";
  default:
    return "WiFi error";
  }
}

static const char *authmode_name(wifi_auth_mode_t mode)
{
  switch (mode)
  {
  case WIFI_AUTH_OPEN:
    return "open";
  case WIFI_AUTH_WEP:
    return "WEP";
  case WIFI_AUTH_WPA_PSK:
    return "WPA";
  case WIFI_AUTH_WPA2_PSK:
    return "WPA2";
  case WIFI_AUTH_WPA_WPA2_PSK:
    return "WPA/WPA2";
  case WIFI_AUTH_WPA3_PSK:
    return "WPA3";
  case WIFI_AUTH_WPA2_WPA3_PSK:
    return "WPA2/WPA3";
  case WIFI_AUTH_OWE:
    return "open (OWE)";
  case WIFI_AUTH_ENTERPRISE:
  case WIFI_AUTH_WPA3_ENTERPRISE:
  case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
  case WIFI_AUTH_WPA3_ENT_192:
    return "enterprise (not supported)";
  default:
    return "other";
  }
}

/* Network interface handles */
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;

/* AP address - moves to another subnet when the uplink network uses the same one */
static char ap_ip_str[16] = WEB_CONFIG_IP;

/* Uplink connectivity state (result of the captive portal probe) */
typedef enum
{
  UPLINK_OFFLINE,     // No STA connection
  UPLINK_CHECKING,    // Connected, probe pending
  UPLINK_PORTAL,      // Captive portal intercepts traffic - login required
  UPLINK_NO_INTERNET, // Connected, but no probe got an answer (blocked portal or no internet)
  UPLINK_ONLINE       // Real internet access confirmed
} uplink_state_t;

/* Connectivity probes - tried in order until one gets an HTTP answer */
typedef struct
{
  const char *url;
  int ok_status;       // status of a free internet connection
  const char *ok_body; // text the body has to contain (NULL = any)
} connectivity_probe_t;

static const connectivity_probe_t CONNECTIVITY_PROBES[] = {
    {"http://connectivitycheck.gstatic.com/generate_204", 204, NULL},
    {"http://captive.apple.com/hotspot-detect.html", 200, "Success"},
    {"http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"},
};
#define PROBE_TIMEOUT_MS 8000
/* Transmit power choices (web panel, P key), 0 = maximum */
static const struct
{
  uint8_t dbm;
  const char *label;
} TX_POWER_OPTIONS[] = {{0, "Maximum (about 20 dBm)"}, {17, "17 dBm"}, {15, "15 dBm"},
                        {13, "13 dBm"}, {11, "11 dBm"}, {8, "8 dBm (lowest)"}};

#define CHECK_INTERVAL_ONLINE_MS 60000 // while online; every status cycle (10 s) otherwise
#define PORTAL_FALLBACK_URL "http://neverssl.com/"
#define FORM_BODY_MAX 3072 // URL encoded settings form

/* Status tracking */
static bool sta_connected = false;
static bool napt_enabled = false;
static uplink_state_t uplink_state = UPLINK_OFFLINE;
static char portal_url[256] = {0};
static char probe_info[192] = {0}; // result of the last connectivity check (web panel diagnostics)

/* Kill switch: client traffic only through the tunnel, except during portal login */
static volatile uint32_t kill_switch_drops = 0;
static bool kill_switch_active(void);

/* Clients' connectivity checks go to this device while the uplink needs a login */
static bool intercept_portal_probes(void)
{
  return stored_config.portal_redirect &&
         (uplink_state == UPLINK_PORTAL || uplink_state == UPLINK_NO_INTERNET);
}

/* WireGuard state */
static wireguard_config_t wg_config = {};
static wireguard_ctx_t wg_ctx = {};
static char wg_ip[16] = {0};
static char wg_netmask[16] = {0};
static bool wg_initialized = false;
static bool wg_connected = false;
static bool wg_peer_up = false;
static char wg_status[96] = "disabled";
static volatile bool wg_toggle_requested = false; // V key, handled in the status task
static bool wg_configured(void);
static int64_t wg_connect_us = 0; // when the tunnel was started

/* Copy of the peer state shown on the debug page */
typedef struct
{
  bool valid;
  ip_addr_t endpoint_ip; // resolved endpoint
  uint16_t endpoint_port;
  ip_addr_t seen_ip; // where answers came from
  uint16_t seen_port;
  uint32_t now;
  uint32_t latest_handshake; // millis timestamps, 0 = never
  uint32_t last_initiation_tx;
  uint32_t last_rx;
  uint32_t last_tx;
} wg_peer_snapshot_t;

static esp_err_t wg_snapshot_cb(void *arg); // runs in the TCP/IP task
static volatile bool wg_is_default = false; // also read in the TCP/IP task (MSS clamping)

static bool kill_switch_active(void)
{
  return stored_config.wg_enabled && stored_config.wg_kill_switch && !wg_is_default &&
         uplink_state != UPLINK_PORTAL && uplink_state != UPLINK_NO_INTERNET;
}

/* Status task handle (notified on uplink changes) */
static TaskHandle_t status_task_handle = NULL;

/* M5Stack Cardputer Display Pin Configuration */
#define LCD_MOSI_PIN 35 // DATA
#define LCD_SCLK_PIN 36 // SCK
#define LCD_CS_PIN 37   // CS
#define LCD_DC_PIN 34   // RS/DC
#define LCD_RST_PIN 33  // RST
#define LCD_BL_PIN 38   // Backlight

#define LCD_H_RES 136
#define LCD_V_RES 240
#define LCD_PIXEL_CLK 40000000

/* M5Stack Cardputer ADV keyboard: TCA8418 key matrix controller on I2C */
#define KEYBOARD_SDA_PIN 8
#define KEYBOARD_SCL_PIN 9
#define TCA8418_ADDR 0x34
#define TCA8418_REG_CFG 0x01
#define TCA8418_REG_INT_STAT 0x02
#define TCA8418_REG_KEY_LCK_EC 0x03
#define TCA8418_REG_KEY_EVENT_A 0x04
#define TCA8418_REG_KP_GPIO_1 0x1D
#define TCA8418_REG_KP_GPIO_2 0x1E
#define TCA8418_REG_KP_GPIO_3 0x1F
#define TCA8418_KEY_PRESSED 0x80
/* Key numbers are row * 10 + column + 1 of the 7x8 matrix (layout as in the
 * M5Cardputer library): V is in the bottom row, 7th key -> matrix row 3, column 3 */
#define KEY_V 34 // VPN on/off
#define KEY_E 16 // eco mode on/off (2nd row, 4th key)
#define KEY_P 52 // next transmit power (2nd row, 11th key)

/* M5Stack Cardputer G0 button and battery */
#define BUTTON_G0_PIN 0            // active low; also a strapping pin (download mode at reset)
#define BATTERY_ADC_PIN 10         // battery voltage through a 1:2 divider
#define BATTERY_DIVIDER 2
#define FACTORY_RESET_HOLD_MS 5000 // hold G0 this long to erase all settings

/* Web Server Configuration */
#define WEB_SERVER_STACK_SIZE 8192

/* Display handles */
static esp_lcd_panel_io_handle_t lcd_io_handle = NULL;
static esp_lcd_panel_handle_t lcd_panel_handle = NULL;
static int ap_client_count = 0;

/* Display power and locking - the screen is drawn from several tasks */
static SemaphoreHandle_t display_mutex = NULL; // recursive, guards framebuffer and backlight
static volatile bool display_on = true;
static volatile bool reset_screen_shown = false; // factory reset countdown owns the screen
static volatile TickType_t last_activity_tick = 0;

/* Battery voltage in mV (smoothed), -1 = unknown */
static int battery_mv = -1;

/* Web server handle */
static httpd_handle_t web_server = NULL;
static bool config_mode = false;

/**
 * RGB565 Color definitions (byte-swapped for ST7789)
 */
#define RGB565(r, g, b) ({                                              \
  uint16_t rgb = ((((r) >> 3) << 11) | (((g) >> 2) << 5) | ((b) >> 3)); \
  ((rgb >> 8) | (rgb << 8));                                            \
})
#define COLOR_BLACK RGB565(0, 0, 0)
#define COLOR_WHITE RGB565(255, 255, 255)
#define COLOR_RED RGB565(255, 0, 0)
#define COLOR_GREEN RGB565(0, 255, 0)
#define COLOR_BLUE RGB565(0, 0, 255)
#define COLOR_YELLOW RGB565(255, 255, 0)
#define COLOR_CYAN RGB565(0, 255, 255)
#define COLOR_NAVY RGB565(0, 0, 128)
#define COLOR_DARKGREEN RGB565(0, 128, 0)
#define COLOR_ORANGE RGB565(255, 165, 0)

// Terminal Green Theme Colors (Classic CRT Green)
#define TERM_BG RGB565(0, 0, 0)          // Pure black background
#define TERM_GREEN RGB565(0, 255, 0)     // Bright pure green (classic terminal)
#define TERM_GREEN_DIM RGB565(0, 180, 0) // Dimmed green
#define TERM_GREEN_DARK RGB565(0, 60, 0) // Dark green for boxes
#define TERM_ACCENT RGB565(50, 255, 50)  // Lighter accent green

// Simple 8x8 font bitmap (ASCII 32-127) - abbreviated for space
static const uint8_t font8x8[96][8] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // space
    {0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00}, // !
    {0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // "
    {0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00}, // #
    {0x0C, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x0C, 0x00}, // $
    {0x00, 0x63, 0x33, 0x18, 0x0C, 0x66, 0x63, 0x00}, // %
    {0x1C, 0x36, 0x1C, 0x6E, 0x3B, 0x33, 0x6E, 0x00}, // &
    {0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00}, // '
    {0x18, 0x0C, 0x06, 0x06, 0x06, 0x0C, 0x18, 0x00}, // (
    {0x06, 0x0C, 0x18, 0x18, 0x18, 0x0C, 0x06, 0x00}, // )
    {0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00}, // *
    {0x00, 0x0C, 0x0C, 0x3F, 0x0C, 0x0C, 0x00, 0x00}, // +
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x06}, // ,
    {0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00}, // -
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x00}, // .
    {0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x01, 0x00}, // /
    {0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00}, // 0
    {0x0C, 0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F, 0x00}, // 1
    {0x1E, 0x33, 0x30, 0x1C, 0x06, 0x33, 0x3F, 0x00}, // 2
    {0x1E, 0x33, 0x30, 0x1C, 0x30, 0x33, 0x1E, 0x00}, // 3
    {0x38, 0x3C, 0x36, 0x33, 0x7F, 0x30, 0x78, 0x00}, // 4
    {0x3F, 0x03, 0x1F, 0x30, 0x30, 0x33, 0x1E, 0x00}, // 5
    {0x1C, 0x06, 0x03, 0x1F, 0x33, 0x33, 0x1E, 0x00}, // 6
    {0x3F, 0x33, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x00}, // 7
    {0x1E, 0x33, 0x33, 0x1E, 0x33, 0x33, 0x1E, 0x00}, // 8
    {0x1E, 0x33, 0x33, 0x3E, 0x30, 0x18, 0x0E, 0x00}, // 9
    {0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x00}, // :
    {0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x06}, // ;
    {0x18, 0x0C, 0x06, 0x03, 0x06, 0x0C, 0x18, 0x00}, // <
    {0x00, 0x00, 0x3F, 0x00, 0x00, 0x3F, 0x00, 0x00}, // =
    {0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00}, // >
    {0x1E, 0x33, 0x30, 0x18, 0x0C, 0x00, 0x0C, 0x00}, // ?
    {0x3E, 0x63, 0x7B, 0x7B, 0x7B, 0x03, 0x1E, 0x00}, // @
    {0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00}, // A
    {0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00}, // B
    {0x3C, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3C, 0x00}, // C
    {0x1F, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1F, 0x00}, // D
    {0x7F, 0x46, 0x16, 0x1E, 0x16, 0x46, 0x7F, 0x00}, // E
    {0x7F, 0x46, 0x16, 0x1E, 0x16, 0x06, 0x0F, 0x00}, // F
    {0x3C, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7C, 0x00}, // G
    {0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00}, // H
    {0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00}, // I
    {0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E, 0x00}, // J
    {0x67, 0x66, 0x36, 0x1E, 0x36, 0x66, 0x67, 0x00}, // K
    {0x0F, 0x06, 0x06, 0x06, 0x46, 0x66, 0x7F, 0x00}, // L
    {0x63, 0x77, 0x7F, 0x7F, 0x6B, 0x63, 0x63, 0x00}, // M
    {0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00}, // N
    {0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00}, // O
    {0x3F, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0F, 0x00}, // P
    {0x1E, 0x33, 0x33, 0x33, 0x3B, 0x1E, 0x38, 0x00}, // Q
    {0x3F, 0x66, 0x66, 0x3E, 0x36, 0x66, 0x67, 0x00}, // R
    {0x1E, 0x33, 0x07, 0x0E, 0x38, 0x33, 0x1E, 0x00}, // S
    {0x3F, 0x2D, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00}, // T
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00}, // U
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00}, // V
    {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00}, // W
    {0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00}, // X
    {0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x1E, 0x00}, // Y
    {0x7F, 0x63, 0x31, 0x18, 0x4C, 0x66, 0x7F, 0x00}, // Z
    {0x1E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1E, 0x00}, // [
    {0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00}, // backslash
    {0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00}, // ]
    {0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00}, // ^
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}, // _
    {0x0C, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00}, // `
    {0x00, 0x00, 0x1E, 0x30, 0x3E, 0x33, 0x6E, 0x00}, // a
    {0x07, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3B, 0x00}, // b
    {0x00, 0x00, 0x1E, 0x33, 0x03, 0x33, 0x1E, 0x00}, // c
    {0x38, 0x30, 0x30, 0x3e, 0x33, 0x33, 0x6E, 0x00}, // d
    {0x00, 0x00, 0x1E, 0x33, 0x3f, 0x03, 0x1E, 0x00}, // e
    {0x1C, 0x36, 0x06, 0x0f, 0x06, 0x06, 0x0F, 0x00}, // f
    {0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x1F}, // g
    {0x07, 0x06, 0x36, 0x6E, 0x66, 0x66, 0x67, 0x00}, // h
    {0x0C, 0x00, 0x0E, 0x0C, 0x0C, 0x0C, 0x1E, 0x00}, // i
    {0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E}, // j
    {0x07, 0x06, 0x66, 0x36, 0x1E, 0x36, 0x67, 0x00}, // k
    {0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00}, // l
    {0x00, 0x00, 0x33, 0x7F, 0x7F, 0x6B, 0x63, 0x00}, // m
    {0x00, 0x00, 0x1F, 0x33, 0x33, 0x33, 0x33, 0x00}, // n
    {0x00, 0x00, 0x1E, 0x33, 0x33, 0x33, 0x1E, 0x00}, // o
    {0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x0F}, // p
    {0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x78}, // q
    {0x00, 0x00, 0x3B, 0x6E, 0x66, 0x06, 0x0F, 0x00}, // r
    {0x00, 0x00, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x00}, // s
    {0x08, 0x0C, 0x3E, 0x0C, 0x0C, 0x2C, 0x18, 0x00}, // t
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6E, 0x00}, // u
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00}, // v
    {0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00}, // w
    {0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00}, // x
    {0x00, 0x00, 0x33, 0x33, 0x33, 0x3E, 0x30, 0x1F}, // y
    {0x00, 0x00, 0x3F, 0x19, 0x0C, 0x26, 0x3F, 0x00}, // z
    {0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00}, // {
    {0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00}, // |
    {0x07, 0x0C, 0x0C, 0x38, 0x0C, 0x0C, 0x07, 0x00}, // }
    {0x6E, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // ~
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // del
};

// Display buffer (rotated: 240x135)
static uint16_t *framebuffer = NULL;

/* ═══════════════════════════════════════════════════════════════════
 * WEB SERVER HTML PAGES
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Send a string as an HTML-escaped response chunk
 */
static void send_html_escaped(httpd_req_t *req, const char *src)
{
  char buf[64];
  size_t pos = 0;
  while (*src)
  {
    const char *rep = NULL;
    switch (*src)
    {
    case '&':
      rep = "&amp;";
      break;
    case '<':
      rep = "&lt;";
      break;
    case '>':
      rep = "&gt;";
      break;
    case '"':
      rep = "&quot;";
      break;
    case '\'':
      rep = "&#39;";
      break;
    }
    size_t need = rep ? strlen(rep) : 1;
    if (pos + need >= sizeof(buf))
    {
      httpd_resp_send_chunk(req, buf, pos);
      pos = 0;
    }
    if (rep)
    {
      memcpy(buf + pos, rep, need);
      pos += need;
    }
    else
    {
      buf[pos++] = *src;
    }
    src++;
  }
  if (pos > 0)
    httpd_resp_send_chunk(req, buf, pos);
}

static const char *html_page_head =
    "<!DOCTYPE html>"
    "<html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>CardRepeater Config</title>"
    "<style>"
    "body{font-family:Arial,sans-serif;margin:20px;background:#f0f0f0}"
    "h1{color:#333;text-align:center;background:#4CAF50;color:white;padding:15px;border-radius:5px}"
    "form{background:white;padding:20px;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,0.1);max-width:500px;margin:20px auto}"
    "label{display:block;margin:10px 0 5px;font-weight:bold;color:#555}"
    "input{width:100%;padding:8px;margin-bottom:15px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}"
    "input[type=checkbox]{width:auto;margin:0 8px 0 0}"
    "select{width:100%;padding:8px;margin-bottom:15px;border:1px solid #ddd;border-radius:4px}"
    "button{background:#4CAF50;color:white;padding:12px 20px;border:none;border-radius:4px;cursor:pointer;width:100%;font-size:16px}"
    "button:hover{background:#45a049}"
    ".row{display:flex;gap:8px}.row input{flex:1}.row button{width:auto;padding:8px 14px;margin-bottom:15px;font-size:14px}"
    ".net{padding:8px;margin:0 0 4px;background:#e8f5e9;border-radius:4px;cursor:pointer;font-size:14px}"
    ".diag{font-size:12px;color:#666;word-break:break-all}"
    ".build{font-size:12px;color:#888;text-align:center;margin:20px auto}"
    ".btn{background:#607d8b;color:#fff;padding:8px 14px;border-radius:4px;text-decoration:none;font-size:14px}"
    ".net:hover{background:#c8e6c9}"
    ".info{background:#e3f2fd;padding:10px;border-radius:4px;margin:10px 0;border-left:4px solid #2196F3}"
    ".section{margin:20px 0;padding:15px;background:#fafafa;border-radius:4px}"
    ".status{text-align:center;padding:10px;margin:10px auto;border-radius:4px;max-width:520px}"
    ".ok{background:#d4edda;color:#155724;border:1px solid #c3e6cb}"
    ".warn{background:#fff3cd;color:#856404;border:1px solid #ffeeba}"
    ".err{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}"
    "</style></head><body>"
    "<h1>CardRepeater Setup</h1>";

static const char *html_page_script =
    "<script>"
    "var target=null;"
    "function scan(){"
    "var n=document.getElementById('nets');n.textContent='Scanning...';"
    "fetch('/scan').then(function(r){if(!r.ok)throw r.status;return r.json()}).then(function(l){"
    "n.textContent='';"
    "if(!l.length){n.textContent='No networks found';return}"
    "l.forEach(function(a){var d=document.createElement('div');d.className='net';"
    "d.textContent=(a.auth?'\\uD83D\\uDD12 ':'')+a.ssid+'  ('+a.rssi+' dBm, ch '+a.ch+')';"
    "d.onclick=function(){var s=target||document.getElementById('sta_ssid');s.value=a.ssid;"
    "var p=document.getElementById(s.id=='sta_ssid'?'sta_pass':s.id.replace('ssid','pass'));"
    "if(p&&!a.auth)p.value='-';n.textContent=''};"
    "n.appendChild(d)})"
    "}).catch(function(e){n.textContent='Scan failed ('+e+') - uplink may be busy connecting, try again'})}"
    "</script>";

/**
 * Send the uplink / VPN status box (normal mode only)
 */
static void send_status_html(httpd_req_t *req)
{
  if (config_mode)
    return;

  switch (uplink_state)
  {
  case UPLINK_ONLINE:
    httpd_resp_sendstr_chunk(req, "<div class='status ok'>Uplink: online");
    break;
  case UPLINK_PORTAL:
    httpd_resp_sendstr_chunk(req, "<div class='status warn'><b>Captive portal detected</b> on the uplink network.<br>"
                                  "<a href='");
    send_html_escaped(req, strlen(portal_url) > 0 ? portal_url : PORTAL_FALLBACK_URL);
    httpd_resp_sendstr_chunk(req, "' target='_blank'>Open the login page</a> - signing in once unlocks internet for all clients.");
    break;
  case UPLINK_NO_INTERNET:
  {
    httpd_resp_sendstr_chunk(req, "<div class='status err'><b>Uplink connected, but no internet access.</b><br>"
                                  "If this network has a login page, try ");
    esp_netif_ip_info_t sta_info;
    if (esp_netif_get_ip_info(sta_netif, &sta_info) == ESP_OK && sta_info.gw.addr != 0)
    {
      char link[96];
      snprintf(link, sizeof(link), "<a href='http://" IPSTR "/' target='_blank'>the gateway</a> or ",
               IP2STR(&sta_info.gw));
      httpd_resp_sendstr_chunk(req, link);
    }
    httpd_resp_sendstr_chunk(req, "<a href='" PORTAL_FALLBACK_URL "' target='_blank'>neverssl.com</a>.");
    break;
  }
  case UPLINK_CHECKING:
    httpd_resp_sendstr_chunk(req, "<div class='status warn'>Uplink: connected, checking internet...");
    break;
  default:
    httpd_resp_sendstr_chunk(req, "<div class='status err'>Uplink: offline");
    break;
  }

  if (stored_config.wg_enabled)
  {
    if (wg_is_default)
      httpd_resp_sendstr_chunk(req, "<br>WireGuard: tunnel up, all client traffic is routed through VPN");
    else if (wg_peer_up)
      httpd_resp_sendstr_chunk(req, "<br>WireGuard: handshake OK, waiting for uplink");
    else
      httpd_resp_sendstr_chunk(req, "<br>WireGuard: connecting...");
    if (kill_switch_active())
      httpd_resp_sendstr_chunk(req, "<br><b>Kill switch: client traffic is blocked until the VPN is up</b>");
  }
  if (sta_open_fallback && sta_connected)
    httpd_resp_sendstr_chunk(req, "<br>Connected without password - the uplink is an open network");
  if (strlen(probe_info) > 0 && uplink_state != UPLINK_OFFLINE)
  {
    httpd_resp_sendstr_chunk(req, "<div class='diag'>Last check: ");
    send_html_escaped(req, probe_info);
    httpd_resp_sendstr_chunk(req, "</div>");
  }
  httpd_resp_sendstr_chunk(req, "</div>");
}

/**
 * Firmware version (git describe, from scripts/build_version.py) and
 * build time from the app description ESP-IDF embeds
 */
static void send_build_info(httpd_req_t *req)
{
  const esp_app_desc_t *app = esp_app_get_description();
  char line[96];
  httpd_resp_sendstr_chunk(req, "<div class='build'>Build ");
#ifdef FIRMWARE_VERSION
  send_html_escaped(req, FIRMWARE_VERSION);
#else
  send_html_escaped(req, app->version);
#endif
  snprintf(line, sizeof(line), " &middot; %.16s %.16s &middot; ESP-IDF ", app->date, app->time);
  httpd_resp_sendstr_chunk(req, line);
  send_html_escaped(req, app->idf_ver);
  httpd_resp_sendstr_chunk(req, "</div>");
}

/**
 * Send the configuration page with prefilled values (chunked)
 */
static void send_config_html(httpd_req_t *req, const repeater_config_t *config)
{
  char num[8];

  httpd_resp_sendstr_chunk(req, html_page_head);
  send_status_html(req);
  httpd_resp_sendstr_chunk(req, "<div class='status' style='display:flex;gap:8px;justify-content:center'>"
                                "<a class='btn' href='/debug?check=1' target='_blank'>Debug info</a>"
                                "<a class='btn' href='/debug?scan=1' target='_blank'>Debug + WiFi scan</a></div>");
  if (!config_mode && strlen(config->admin_password) == 0)
    httpd_resp_sendstr_chunk(req, "<div class='status err'>The web panel has no password yet - anyone on this "
                                  "network can change these settings. Set one under Device.</div>");

  httpd_resp_sendstr_chunk(req,
                           "<form action='/save' method='POST'>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>Uplink WiFi</h2>"
                           "<label>Network Name (SSID):</label>"
                           "<div class='row'><input type='text' id='sta_ssid' name='sta_ssid' onfocus='target=this' value='");
  send_html_escaped(req, config->sta_ssid);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='Your WiFi network name' required>"
                           "<button type='button' onclick='scan()'>Scan</button></div>"
                           "<div id='nets'></div>"
                           "<label>Password:</label>"
                           "<input type='password' id='sta_pass' name='sta_pass' placeholder='");
  httpd_resp_sendstr_chunk(req, strlen(config->sta_password) > 0 ? "Blank keeps current, - removes it (open network)"
                                                                  : "Leave empty for an open network");
  httpd_resp_sendstr_chunk(req, "'><label>Other saved networks (the strongest one in range is used):</label>");
  for (int i = 0; i < 4; i++)
  {
    char field[160];
    snprintf(field, sizeof(field),
             "<div class='row'><input type='text' id='ssid%d' name='ssid%d' onfocus='target=this' "
             "placeholder='Network name' value='",
             i + 2, i + 2);
    httpd_resp_sendstr_chunk(req, field);
    send_html_escaped(req, config->extra_ssid[i]);
    snprintf(field, sizeof(field), "'><input type='password' id='pass%d' name='pass%d' placeholder='%s'></div>", i + 2,
             i + 2, strlen(config->extra_password[i]) > 0 ? "Blank keeps, - removes" : "Password");
    httpd_resp_sendstr_chunk(req, field);
  }
  httpd_resp_sendstr_chunk(req,
                           "<div class='info'>Click a field, then a network from the scan to fill it in. "
                           "Empty name removes a network.</div>"
                           "</div>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>Access Point</h2>"
                           "<label>AP Name (SSID):</label>"
                           "<input type='text' name='ap_ssid' value='");
  send_html_escaped(req, config->ap_ssid);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='CardRepeater' required>"
                           "<label>AP Password:</label>"
                           "<input type='password' name='ap_pass' placeholder='");
  httpd_resp_sendstr_chunk(req, strlen(config->ap_password) > 0 ? "Leave blank to keep current or empty for open" : "Leave empty for open network");
  httpd_resp_sendstr_chunk(req,
                           "'><div class='info'>Note: Password must be at least 8 characters or leave empty for open network</div>"
                           "</div>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>WireGuard VPN</h2>"
                           "<label><input type='checkbox' name='wg_en' value='1'");
  if (config->wg_enabled)
    httpd_resp_sendstr_chunk(req, " checked");
  httpd_resp_sendstr_chunk(req,
                           ">Route all client traffic through WireGuard</label>"
                           "<label>Interface Address:</label>"
                           "<input type='text' name='wg_addr' value='");
  send_html_escaped(req, config->wg_address);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='10.6.0.2/32'>"
                           "<label>Private Key:</label>"
                           "<input type='password' name='wg_priv' placeholder='");
  httpd_resp_sendstr_chunk(req, strlen(config->wg_private_key) > 0 ? "Leave blank to keep current" : "Output of wg genkey");
  httpd_resp_sendstr_chunk(req,
                           "'><label>Peer Public Key:</label>"
                           "<input type='text' name='wg_peer' value='");
  send_html_escaped(req, config->wg_peer_public_key);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='Server public key'>"
                           "<label>Preshared Key (optional):</label>"
                           "<input type='password' name='wg_psk' placeholder='");
  httpd_resp_sendstr_chunk(req, strlen(config->wg_preshared_key) > 0 ? "Blank keeps current, - removes it" : "Leave empty if not used");
  httpd_resp_sendstr_chunk(req,
                           "'><label>Endpoint (host):</label>"
                           "<input type='text' name='wg_host' value='");
  send_html_escaped(req, config->wg_endpoint);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='vpn.example.com'>"
                           "<label>Endpoint Port:</label>"
                           "<input type='number' name='wg_port' min='1' max='65535' value='");
  snprintf(num, sizeof(num), "%u", config->wg_port);
  httpd_resp_sendstr_chunk(req, num);
  httpd_resp_sendstr_chunk(req,
                           "'><label>Persistent Keepalive (seconds):</label>"
                           "<input type='number' name='wg_ka' min='1' max='65535' value='");
  snprintf(num, sizeof(num), "%u", config->wg_keepalive);
  httpd_resp_sendstr_chunk(req, num);
  httpd_resp_sendstr_chunk(req,
                           "'><label>DNS for clients (optional):</label>"
                           "<input type='text' name='wg_dns' value='");
  send_html_escaped(req, config->wg_dns);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='e.g. 1.1.1.1 (empty = uplink DNS)'>"
                           "<label><input type='checkbox' name='wg_kill' value='1'");
  if (config->wg_kill_switch)
    httpd_resp_sendstr_chunk(req, " checked");
  httpd_resp_sendstr_chunk(req,
                           ">Block client traffic while the VPN is down (kill switch)</label>"
                           "<div class='info'>The tunnel uses AllowedIPs 0.0.0.0/0. Traffic switches to the VPN "
                           "after a successful handshake and while the uplink has internet access. "
                           "During captive portal login clients always reach the network directly - "
                           "with the kill switch, at all other times only through the VPN.</div>"
                           "</div>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>Device</h2>"
                           "<label>Admin Password (web panel login):</label>"
                           "<input type='password' name='admin_pass' maxlength='63' placeholder='");
  if (strlen(config->admin_password) > 0)
    httpd_resp_sendstr_chunk(req, "Leave blank to keep current'>");
  else
    httpd_resp_sendstr_chunk(req, "At least 8 characters' minlength='8' required>");
  httpd_resp_sendstr_chunk(req,
                           "<label>Screen Timeout (seconds, 0 = always on):</label>"
                           "<input type='number' name='disp_off' min='0' max='65535' value='");
  snprintf(num, sizeof(num), "%u", config->display_timeout);
  httpd_resp_sendstr_chunk(req, num);
  httpd_resp_sendstr_chunk(req, "'><label><input type='checkbox' name='portal_redir' value='1'");
  if (config->portal_redirect)
    httpd_resp_sendstr_chunk(req, " checked");
  httpd_resp_sendstr_chunk(req,
                           ">Open the uplink's login page on clients (captive portal)</label>"
                           "<div class='info'>While the uplink network needs a login, phones and laptops "
                           "show their \"Sign in to network\" page on their own. Clients use this device as DNS server.</div>"
                           "<div class='info'>Log in with any user name and the admin password. "
                           "Press G0 to wake the screen; hold G0 for 5 seconds to erase all settings.</div>"
                           "</div>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>Battery</h2>"
                           "<label>WiFi transmit power:</label><select name='tx_pwr'>");
  for (size_t i = 0; i < sizeof(TX_POWER_OPTIONS) / sizeof(TX_POWER_OPTIONS[0]); i++)
  {
    char option[80];
    snprintf(option, sizeof(option), "<option value='%u'%s>%s</option>", (unsigned)TX_POWER_OPTIONS[i].dbm,
             config->tx_power == TX_POWER_OPTIONS[i].dbm ? " selected" : "", TX_POWER_OPTIONS[i].label);
    httpd_resp_sendstr_chunk(req, option);
  }
  httpd_resp_sendstr_chunk(req, "</select><label><input type='checkbox' name='eco' value='1'");
  if (config->eco_mode)
    httpd_resp_sendstr_chunk(req, " checked");
  httpd_resp_sendstr_chunk(req,
                           ">Eco mode: CPU at 80-160 MHz instead of 240 MHz</label>"
                           "<div class='info'>Lower transmit power saves the most while the uplink and the clients "
                           "are close; it reduces the range. Eco mode saves some more and lowers the top speed a "
                           "little (usually still above what hotel WiFi gives). While online, internet access is "
                           "checked every minute.</div>"
                           "</div>"
                           "<button type='submit'>Save & Restart</button>"
                           "</form>"
                           "<div class='status warn'>Device will restart after saving configuration</div>");
  send_build_info(req);
  httpd_resp_sendstr_chunk(req, html_page_script);
  httpd_resp_sendstr_chunk(req, "</body></html>");
  httpd_resp_sendstr_chunk(req, NULL);
}

static const char *html_success_page =
    "<!DOCTYPE html>"
    "<html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='refresh' content='10;url=/'>"
    "<title>Config Saved</title>"
    "<style>"
    "body{font-family:Arial,sans-serif;margin:20px;background:#f0f0f0;text-align:center;padding-top:50px}"
    ".success{background:#d4edda;color:#155724;padding:30px;border-radius:5px;max-width:500px;margin:0 auto;box-shadow:0 2px 4px rgba(0,0,0,0.1)}"
    "h1{color:#155724;margin-top:0}"
    ".spinner{border:4px solid #f3f3f3;border-top:4px solid #4CAF50;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto}"
    "@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}"
    "</style></head><body>"
    "<div class='success'>"
    "<h1>Configuration Saved!</h1>"
    "<p>Your WiFi settings have been saved successfully.</p>"
    "<p>The device is restarting...</p>"
    "<div class='spinner'></div>"
    "<p style='color:#666;font-size:14px'>This page will refresh in 10 seconds</p>"
    "</div></body></html>";

/**
 * Fill screen with a color
 */
static void lcd_fill_screen(uint16_t color)
{
  if (!framebuffer)
    return;

  for (int i = 0; i < LCD_V_RES * LCD_H_RES; i++)
  {
    framebuffer[i] = color;
  }
}

/**
 * Draw a character at position (x, y)
 */
static void lcd_draw_char(int x, int y, char c, uint16_t color, uint16_t bg_color)
{
  if (!framebuffer || c < 32 || c > 127)
    return;

  const uint8_t *glyph = font8x8[c - 32];

  for (int py = 0; py < 8; py++)
  {
    uint8_t line = glyph[py];
    for (int px = 0; px < 8; px++)
    {
      int screen_x = x + px;
      int screen_y = y + py;

      if (screen_x >= 0 && screen_x < LCD_V_RES && screen_y >= 0 && screen_y < LCD_H_RES)
      {
        // Check bit from LSB side (bit 0 = leftmost pixel)
        bool pixel_on = (line & (1 << px));
        framebuffer[screen_y * LCD_V_RES + screen_x] = pixel_on ? color : bg_color;
      }
    }
  }
}

/**
 * Draw a string at position (x, y)
 */
static void lcd_draw_string(int x, int y, const char *str, uint16_t color, uint16_t bg_color)
{
  int cursor_x = x;
  while (*str)
  {
    lcd_draw_char(cursor_x, y, *str, color, bg_color);
    cursor_x += 8;
    str++;
  }
}

/**
 * Draw a filled rectangle
 */
static void lcd_fill_rect(int x, int y, int w, int h, uint16_t color)
{
  if (!framebuffer)
    return;

  for (int py = 0; py < h; py++)
  {
    for (int px = 0; px < w; px++)
    {
      int screen_x = x + px;
      int screen_y = y + py;

      if (screen_x >= 0 && screen_x < LCD_V_RES && screen_y >= 0 && screen_y < LCD_H_RES)
      {
        framebuffer[screen_y * LCD_V_RES + screen_x] = color;
      }
    }
  }
}

/**
 * Flush framebuffer to display
 */
static void lcd_flush(void)
{
  if (!lcd_panel_handle || !framebuffer)
    return;
  esp_lcd_panel_draw_bitmap(lcd_panel_handle, 0, 0, LCD_V_RES, LCD_H_RES, framebuffer);
}

/**
 * Initialize Display
 */
static void display_init(void)
{
  display_mutex = xSemaphoreCreateRecursiveMutex();

  ESP_LOGI(TAG_MAIN, "Initializing SPI bus for LCD");

  // Configure backlight - turn OFF first, then ON after display init
  gpio_config_t bk_gpio_config = {
      .pin_bit_mask = 1ULL << LCD_BL_PIN,
      .mode = GPIO_MODE_OUTPUT,
  };
  gpio_config(&bk_gpio_config);
  gpio_set_level((gpio_num_t)LCD_BL_PIN, 0); // Turn off initially
  ESP_LOGI(TAG_MAIN, "Backlight pin %d configured (OFF for now)", LCD_BL_PIN);

  // Configure SPI bus
  spi_bus_config_t buscfg = {
      .mosi_io_num = LCD_MOSI_PIN,
      .miso_io_num = -1,
      .sclk_io_num = LCD_SCLK_PIN,
      .quadwp_io_num = -1,
      .quadhd_io_num = -1,
      .max_transfer_sz = LCD_H_RES * LCD_V_RES * sizeof(uint16_t),
  };
  ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO));

  // Configure LCD panel IO
  esp_lcd_panel_io_spi_config_t io_config = {
      .cs_gpio_num = LCD_CS_PIN,
      .dc_gpio_num = LCD_DC_PIN,
      .spi_mode = 0,
      .pclk_hz = LCD_PIXEL_CLK,
      .trans_queue_depth = 10,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
  };
  ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &io_config, &lcd_io_handle));

  // Configure LCD panel
  esp_lcd_panel_dev_config_t panel_config = {
      .reset_gpio_num = LCD_RST_PIN,
      .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
      .bits_per_pixel = 16,
  };
  ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(lcd_io_handle, &panel_config, &lcd_panel_handle));

  // Reset and initialize panel
  ESP_LOGI(TAG_MAIN, "Resetting display...");
  esp_lcd_panel_reset(lcd_panel_handle);
  vTaskDelay(pdMS_TO_TICKS(100));

  ESP_LOGI(TAG_MAIN, "Initializing display...");
  esp_lcd_panel_init(lcd_panel_handle);
  vTaskDelay(pdMS_TO_TICKS(100));

  ESP_LOGI(TAG_MAIN, "Setting display orientation and gap");

  // ST7789V2 on M5Stack Cardputer needs these settings
  esp_lcd_panel_invert_color(lcd_panel_handle, true);

  // Set gap for 135x240 display (52x40 offset)
  esp_lcd_panel_set_gap(lcd_panel_handle, 40, 52);

  // Set orientation - landscape mode for 240x135
  // Swap XY to rotate from portrait to landscape
  esp_lcd_panel_swap_xy(lcd_panel_handle, true);
  // Mirror to get correct orientation
  esp_lcd_panel_mirror(lcd_panel_handle, true, false);

  // Turn display on
  ESP_LOGI(TAG_MAIN, "Turning display ON");
  esp_lcd_panel_disp_on_off(lcd_panel_handle, true);
  vTaskDelay(pdMS_TO_TICKS(100));

  // Now turn on backlight
  ESP_LOGI(TAG_MAIN, "Turning backlight ON");
  gpio_set_level((gpio_num_t)LCD_BL_PIN, 1);
  vTaskDelay(pdMS_TO_TICKS(100));

  // Allocate framebuffer
  framebuffer = (uint16_t *)heap_caps_malloc(LCD_V_RES * LCD_H_RES * sizeof(uint16_t), MALLOC_CAP_DMA);
  if (!framebuffer)
  {
    ESP_LOGE(TAG_MAIN, "Failed to allocate framebuffer");
    return;
  }

  ESP_LOGI(TAG_MAIN, "Display ready: %dx%d, framebuffer: %p", LCD_V_RES, LCD_H_RES, framebuffer);

  // Draw initial splash screen
  lcd_fill_screen(TERM_BG);

  // Header
  lcd_fill_rect(0, 0, 240, 18, TERM_GREEN_DARK);
  lcd_draw_string(50, 5, "WiFi REPEATER", TERM_GREEN, TERM_GREEN_DARK);

  // Status message
  lcd_draw_string(30, 50, "Initializing...", TERM_ACCENT, TERM_BG);
  lcd_draw_string(30, 70, "Starting WiFi", TERM_GREEN_DIM, TERM_BG);

  lcd_flush();

  ESP_LOGI(TAG_MAIN, "Display initialized successfully");
}

/* ═══════════════════════════════════════════════════════════════════
 * BATTERY
 * ═══════════════════════════════════════════════════════════════════ */

static adc_oneshot_unit_handle_t battery_adc = NULL;
static adc_channel_t battery_channel;
static adc_cali_handle_t battery_cali = NULL;

/**
 * Set up the ADC for the battery voltage (GPIO10, 1:2 divider)
 */
static void battery_init(void)
{
  adc_unit_t unit;
  if (adc_oneshot_io_to_channel(BATTERY_ADC_PIN, &unit, &battery_channel) != ESP_OK)
    return;

  adc_oneshot_unit_init_cfg_t unit_config = {};
  unit_config.unit_id = unit;
  if (adc_oneshot_new_unit(&unit_config, &battery_adc) != ESP_OK)
  {
    ESP_LOGW(TAG_MAIN, "Battery ADC not available");
    battery_adc = NULL;
    return;
  }

  adc_oneshot_chan_cfg_t channel_config = {};
  channel_config.atten = ADC_ATTEN_DB_12;
  channel_config.bitwidth = ADC_BITWIDTH_12;
  adc_oneshot_config_channel(battery_adc, battery_channel, &channel_config);

  adc_cali_curve_fitting_config_t cali_config = {};
  cali_config.unit_id = unit;
  cali_config.chan = battery_channel;
  cali_config.atten = ADC_ATTEN_DB_12;
  cali_config.bitwidth = ADC_BITWIDTH_12;
  if (adc_cali_create_scheme_curve_fitting(&cali_config, &battery_cali) != ESP_OK)
    battery_cali = NULL;
}

/**
 * Measure the battery voltage (16 samples, smoothed over time)
 */
static void battery_sample(void)
{
  if (!battery_adc)
    return;

  int sum = 0;
  int count = 0;
  for (int i = 0; i < 16; i++)
  {
    int raw, mv;
    if (adc_oneshot_read(battery_adc, battery_channel, &raw) != ESP_OK)
      continue;
    if (battery_cali && adc_cali_raw_to_voltage(battery_cali, raw, &mv) == ESP_OK)
      sum += mv;
    else
      sum += raw * 3100 / 4095; // uncalibrated estimate for 12 dB attenuation
    count++;
  }
  if (count == 0)
    return;

  int mv = sum / count * BATTERY_DIVIDER;
  battery_mv = battery_mv < 0 ? mv : (battery_mv * 3 + mv) / 4;
}

/**
 * Battery level in percent - same mapping as M5Unified (3.3 V = 0 %, 4.1 V = 100 %)
 */
static int battery_percent(void)
{
  int level = (battery_mv - 3300) * 100 / 800;
  return level < 0 ? 0 : (level > 100 ? 100 : level);
}

/* ═══════════════════════════════════════════════════════════════════
 * WEB SERVER HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * URL decode helper function
 */
static void url_decode(char *dst, const char *src)
{
  char a, b;
  while (*src)
  {
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b)))
    {
      if (a >= 'a')
        a -= 'a' - 'A';
      if (a >= 'A')
        a -= ('A' - 10);
      else
        a -= '0';
      if (b >= 'a')
        b -= 'a' - 'A';
      if (b >= 'A')
        b -= ('A' - 10);
      else
        b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
    }
    else if (*src == '+')
    {
      *dst++ = ' ';
      src++;
    }
    else
    {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

/**
 * Parse URL query parameters and extract form fields
 */
static bool parse_query_param(const char *query, const char *field_name, char *output, size_t output_len)
{
  if (!query)
    return false;

  char search_key[64];
  snprintf(search_key, sizeof(search_key), "%s=", field_name);

  // Match only whole field names (at the start or right after '&')
  const char *start = query;
  while ((start = strstr(start, search_key)) != NULL)
  {
    if (start == query || start[-1] == '&')
      break;
    start++;
  }
  if (!start)
    return false;

  start += strlen(search_key);
  const char *end = strchr(start, '&');
  size_t len = end ? (end - start) : strlen(start);

  if (len >= output_len)
    len = output_len - 1;

  char temp[128];
  if (len >= sizeof(temp))
    len = sizeof(temp) - 1;

  strncpy(temp, start, len);
  temp[len] = '\0';

  url_decode(output, temp);
  return true;
}

/**
 * Save WiFi configuration to NVS
 */
static esp_err_t save_wifi_config(const repeater_config_t *config)
{
  nvs_handle_t nvs_handle;
  esp_err_t err;

  err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK)
  {
    ESP_LOGE(TAG_MAIN, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  // Save all configuration values
  nvs_set_u8(nvs_handle, NVS_KEY_CONFIGURED, 1);
  nvs_set_str(nvs_handle, NVS_KEY_STA_SSID, config->sta_ssid);
  nvs_set_str(nvs_handle, NVS_KEY_STA_PASS, config->sta_password);
  for (int i = 0; i < 4; i++)
  {
    char key[16];
    snprintf(key, sizeof(key), "sta_ssid%d", i + 2);
    nvs_set_str(nvs_handle, key, config->extra_ssid[i]);
    snprintf(key, sizeof(key), "sta_pass%d", i + 2);
    nvs_set_str(nvs_handle, key, config->extra_password[i]);
  }
  nvs_set_str(nvs_handle, NVS_KEY_AP_SSID, config->ap_ssid);
  nvs_set_str(nvs_handle, NVS_KEY_AP_PASS, config->ap_password);

  nvs_set_u8(nvs_handle, NVS_KEY_WG_ENABLED, config->wg_enabled ? 1 : 0);
  nvs_set_str(nvs_handle, NVS_KEY_WG_PRIVATE_KEY, config->wg_private_key);
  nvs_set_str(nvs_handle, NVS_KEY_WG_ADDRESS, config->wg_address);
  nvs_set_str(nvs_handle, NVS_KEY_WG_PEER_KEY, config->wg_peer_public_key);
  nvs_set_str(nvs_handle, NVS_KEY_WG_PSK, config->wg_preshared_key);
  nvs_set_str(nvs_handle, NVS_KEY_WG_ENDPOINT, config->wg_endpoint);
  nvs_set_u16(nvs_handle, NVS_KEY_WG_PORT, config->wg_port);
  nvs_set_u16(nvs_handle, NVS_KEY_WG_KEEPALIVE, config->wg_keepalive);
  nvs_set_str(nvs_handle, NVS_KEY_WG_DNS, config->wg_dns);
  nvs_set_u8(nvs_handle, NVS_KEY_WG_KILL_SWITCH, config->wg_kill_switch ? 1 : 0);

  nvs_set_str(nvs_handle, NVS_KEY_ADMIN_PASS, config->admin_password);
  nvs_set_u16(nvs_handle, NVS_KEY_DISPLAY_TIMEOUT, config->display_timeout);
  nvs_set_u8(nvs_handle, NVS_KEY_PORTAL_REDIRECT, config->portal_redirect ? 1 : 0);
  nvs_set_u8(nvs_handle, NVS_KEY_TX_POWER, config->tx_power);
  nvs_set_u8(nvs_handle, NVS_KEY_ECO_MODE, config->eco_mode ? 1 : 0);

  err = nvs_commit(nvs_handle);
  nvs_close(nvs_handle);

  if (err == ESP_OK)
  {
    ESP_LOGI(TAG_MAIN, "✓ Configuration saved to NVS");
  }
  return err;
}

/**
 * Load WiFi configuration from NVS
 */
static esp_err_t load_wifi_config(repeater_config_t *config)
{
  nvs_handle_t nvs_handle;
  esp_err_t err;

  err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
  if (err != ESP_OK)
  {
    return err;
  }

  uint8_t configured = 0;
  size_t len;

  err = nvs_get_u8(nvs_handle, NVS_KEY_CONFIGURED, &configured);
  if (err != ESP_OK || configured != 1)
  {
    nvs_close(nvs_handle);
    return ESP_ERR_NVS_NOT_FOUND;
  }

  // Load all strings
  len = sizeof(config->sta_ssid);
  nvs_get_str(nvs_handle, NVS_KEY_STA_SSID, config->sta_ssid, &len);

  len = sizeof(config->sta_password);
  nvs_get_str(nvs_handle, NVS_KEY_STA_PASS, config->sta_password, &len);

  // More uplink networks (absent in configs saved by older firmware)
  for (int i = 0; i < 4; i++)
  {
    char key[16];
    snprintf(key, sizeof(key), "sta_ssid%d", i + 2);
    len = sizeof(config->extra_ssid[i]);
    nvs_get_str(nvs_handle, key, config->extra_ssid[i], &len);
    snprintf(key, sizeof(key), "sta_pass%d", i + 2);
    len = sizeof(config->extra_password[i]);
    nvs_get_str(nvs_handle, key, config->extra_password[i], &len);
  }

  len = sizeof(config->ap_ssid);
  nvs_get_str(nvs_handle, NVS_KEY_AP_SSID, config->ap_ssid, &len);

  len = sizeof(config->ap_password);
  nvs_get_str(nvs_handle, NVS_KEY_AP_PASS, config->ap_password, &len);

  // WireGuard settings (absent in configs saved by older firmware)
  uint8_t wg_enabled = 0;
  nvs_get_u8(nvs_handle, NVS_KEY_WG_ENABLED, &wg_enabled);
  config->wg_enabled = (wg_enabled == 1);

  len = sizeof(config->wg_private_key);
  nvs_get_str(nvs_handle, NVS_KEY_WG_PRIVATE_KEY, config->wg_private_key, &len);

  len = sizeof(config->wg_address);
  nvs_get_str(nvs_handle, NVS_KEY_WG_ADDRESS, config->wg_address, &len);

  len = sizeof(config->wg_peer_public_key);
  nvs_get_str(nvs_handle, NVS_KEY_WG_PEER_KEY, config->wg_peer_public_key, &len);

  len = sizeof(config->wg_preshared_key);
  nvs_get_str(nvs_handle, NVS_KEY_WG_PSK, config->wg_preshared_key, &len);

  len = sizeof(config->wg_endpoint);
  nvs_get_str(nvs_handle, NVS_KEY_WG_ENDPOINT, config->wg_endpoint, &len);

  nvs_get_u16(nvs_handle, NVS_KEY_WG_PORT, &config->wg_port);
  nvs_get_u16(nvs_handle, NVS_KEY_WG_KEEPALIVE, &config->wg_keepalive);

  len = sizeof(config->wg_dns);
  nvs_get_str(nvs_handle, NVS_KEY_WG_DNS, config->wg_dns, &len);
  uint8_t kill_switch = 0;
  nvs_get_u8(nvs_handle, NVS_KEY_WG_KILL_SWITCH, &kill_switch);
  config->wg_kill_switch = (kill_switch == 1);

  // Device settings (absent in configs saved by older firmware)
  len = sizeof(config->admin_password);
  nvs_get_str(nvs_handle, NVS_KEY_ADMIN_PASS, config->admin_password, &len);
  nvs_get_u16(nvs_handle, NVS_KEY_DISPLAY_TIMEOUT, &config->display_timeout);

  // Portal redirect is on unless it was switched off
  uint8_t portal_redirect = 1;
  nvs_get_u8(nvs_handle, NVS_KEY_PORTAL_REDIRECT, &portal_redirect);
  config->portal_redirect = (portal_redirect == 1);

  // Power settings (absent in configs saved by older firmware: full power)
  nvs_get_u8(nvs_handle, NVS_KEY_TX_POWER, &config->tx_power);
  uint8_t eco_mode = 0;
  nvs_get_u8(nvs_handle, NVS_KEY_ECO_MODE, &eco_mode);
  config->eco_mode = (eco_mode == 1);

  config->configured = true;
  nvs_close(nvs_handle);

  ESP_LOGI(TAG_MAIN, "✓ Configuration loaded from NVS");
  return ESP_OK;
}

/**
 * Clear configuration from NVS
 */
static esp_err_t clear_wifi_config(void)
{
  nvs_handle_t nvs_handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
  if (err == ESP_OK)
  {
    nvs_erase_all(nvs_handle);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
    ESP_LOGI(TAG_MAIN, "✓ Configuration cleared");
  }
  return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * UPLINK RECONNECT
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Configure the uplink connection. Without a password any network is
 * accepted (open hotel/airport WiFi). With a password only WPA2 or
 * better, so a fake open network with the same name is not joined -
 * unless open is set: the saved network itself is open (see the
 * fallback in the disconnect handler).
 */
static esp_err_t apply_sta_config(bool open)
{
  const char *ssid = network_ssid(active_network);
  const char *password = network_password(active_network);
  wifi_config_t wifi_sta_config = {};
  memcpy(wifi_sta_config.sta.ssid, ssid, strlen(ssid));
  bool use_password = !open && strlen(password) > 0;
  if (use_password)
    memcpy(wifi_sta_config.sta.password, password, strlen(password));
  wifi_sta_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  wifi_sta_config.sta.failure_retry_cnt = WIFI_STA_DRIVER_RETRIES;
  wifi_sta_config.sta.threshold.authmode = use_password ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
  wifi_sta_config.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
  wifi_sta_config.sta.owe_enabled = !use_password; // "Enhanced Open" networks
  return esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config);
}

/**
 * Reconnect to the uplink after a growing delay (1 s, 2 s, 4 s ... 60 s).
 * Never gives up - hotel WiFi drops out and comes back.
 */
static void schedule_reconnect(void)
{
  if (!reconnect_timer)
    return;

  ESP_LOGI(TAG_STA, "Reconnecting in %lu s", (unsigned long)(reconnect_delay_ms / 1000));
  esp_timer_stop(reconnect_timer); // fails harmlessly when not running
  esp_timer_start_once(reconnect_timer, (uint64_t)reconnect_delay_ms * 1000);
  reconnect_delay_ms = reconnect_delay_ms * 2 > WIFI_RECONNECT_MAX_MS ? WIFI_RECONNECT_MAX_MS : reconnect_delay_ms * 2;
}

/*
 * With several saved networks a scan picks the strongest one in range
 * (WIFI_EVENT_SCAN_DONE in the event handler), otherwise connect directly
 */
static volatile bool uplink_scan_pending = false;

static esp_err_t start_uplink_connect(void)
{
  if (saved_network_count() > 1)
  {
    wifi_scan_config_t scan_config = {};
    uplink_scan_pending = true;
    if (esp_wifi_scan_start(&scan_config, false) == ESP_OK)
      return ESP_OK;
    uplink_scan_pending = false; // e.g. a scan from the web panel is running - try the current network
  }
  return esp_wifi_connect();
}

/* Scan done: switch to the strongest saved network (records are sorted by RSSI) */
static void uplink_scan_done(void)
{
  uint16_t count = 20;
  wifi_ap_record_t *records = (wifi_ap_record_t *)calloc(count, sizeof(wifi_ap_record_t));
  int best = -1;
  int best_rssi = 0;
  if (records && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK)
  {
    for (int r = 0; r < count && best < 0; r++)
      for (int i = 0; i < UPLINK_NETWORKS && best < 0; i++)
        if (network_ssid(i)[0] != '\0' && strcmp((const char *)records[r].ssid, network_ssid(i)) == 0)
        {
          best = i;
          best_rssi = records[r].rssi;
        }
  }
  else
  {
    esp_wifi_clear_ap_list();
  }
  free(records);

  if (best < 0)
  {
    // Not in range, or a hidden network - try the current one (directed probe)
    ESP_LOGW(TAG_STA, "Uplink: no saved network found by the scan, trying \"%s\"", network_ssid(active_network));
  }
  else if (best != active_network)
  {
    ESP_LOGI(TAG_STA, "Uplink: picked \"%s\" (%d dBm)", network_ssid(best), best_rssi);
    active_network = best;
    sta_open_fallback = false;
    apply_sta_config(false);
  }

  esp_err_t err = esp_wifi_connect();
  if (err != ESP_OK)
  {
    ESP_LOGW(TAG_STA, "Connect failed to start: %s", esp_err_to_name(err));
    schedule_reconnect();
  }
}

static void reconnect_timer_cb(void *arg)
{
  esp_err_t err = start_uplink_connect();
  if (err != ESP_OK)
  {
    ESP_LOGW(TAG_STA, "Connect failed to start: %s", esp_err_to_name(err));
    schedule_reconnect();
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * WEB SERVER HTTP HANDLERS
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * HTTP Basic authentication for the web panel: any user name, the admin password.
 * Sends 401 and returns false if the request is not authorized.
 */
static bool check_auth(httpd_req_t *req)
{
  // No password in setup mode and in configs saved by older firmware
  if (strlen(stored_config.admin_password) == 0)
    return true;

  char header[192];
  if (httpd_req_get_hdr_value_str(req, "Authorization", header, sizeof(header)) == ESP_OK &&
      strncmp(header, "Basic ", 6) == 0)
  {
    unsigned char credentials[144];
    size_t len = 0;
    if (mbedtls_base64_decode(credentials, sizeof(credentials) - 1, &len,
                              (const unsigned char *)header + 6, strlen(header + 6)) == 0)
    {
      credentials[len] = '\0';
      const char *password = strchr((const char *)credentials, ':');
      if (password && strcmp(password + 1, stored_config.admin_password) == 0)
        return true;
    }
  }

  httpd_resp_set_status(req, "401 Unauthorized");
  httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"CardRepeater\"");
  httpd_resp_sendstr(req, "Login required");
  return false;
}

/**
 * Block cross-site form posts: browsers send the origin of the page that
 * submits a form, which has to be this device
 */
static bool is_same_origin(httpd_req_t *req)
{
  char origin[80], host[64], expected[80];
  esp_err_t err = httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin));
  if (err == ESP_ERR_NOT_FOUND)
    return true; // not sent by all clients
  if (err != ESP_OK || httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK)
    return false;
  snprintf(expected, sizeof(expected), "http://%s", host);
  return strcmp(origin, expected) == 0;
}

/* What operating systems expect from their connectivity checks on a free connection */
typedef struct
{
  const char *path;
  const char *status;
  const char *body;
} probe_answer_t;

static const probe_answer_t PROBE_ANSWERS[] = {
    {"/generate_204", "204 No Content", ""},
    {"/gen_204", "204 No Content", ""},
    {"/hotspot-detect.html", "200 OK", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
    {"/library/test/success.html", "200 OK", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
    {"/connecttest.txt", "200 OK", "Microsoft Connect Test"},
    {"/ncsi.txt", "200 OK", "Microsoft NCSI"},
    {"/success.txt", "200 OK", "success\n"},
    {"/canonical.html", "200 OK", "<meta http-equiv=\"refresh\" content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>"},
};

/**
 * Connectivity checks of clients reach this server through the DNS proxy
 * (their Host header is not our address). While the uplink needs a login
 * they are redirected to the login page, which makes the client open it.
 * Returns true when the request was such a check and has been answered.
 */
static bool handle_portal_probe(httpd_req_t *req)
{
  if (config_mode)
    return false;

  char host[80];
  if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_ERR_NOT_FOUND)
    return false;
  char *port = strchr(host, ':');
  if (port)
    *port = '\0';
  if (strcmp(host, ap_ip_str) == 0)
    return false;

  httpd_resp_set_hdr(req, "Cache-Control", "no-store");

  if (intercept_portal_probes())
  {
    char location[sizeof(portal_url)];
    if (uplink_state == UPLINK_PORTAL)
      strlcpy(location, strlen(portal_url) > 0 ? portal_url : PORTAL_FALLBACK_URL, sizeof(location));
    else
      snprintf(location, sizeof(location), "http://%s/portal", ap_ip_str);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_send(req, NULL, 0);
    return true;
  }

  // Login done but the client still has our address cached - give the free connection answer
  char path[64];
  strlcpy(path, req->uri, sizeof(path));
  char *query = strchr(path, '?');
  if (query)
    *query = '\0';
  for (size_t i = 0; i < sizeof(PROBE_ANSWERS) / sizeof(PROBE_ANSWERS[0]); i++)
  {
    if (strcmp(path, PROBE_ANSWERS[i].path) == 0)
    {
      httpd_resp_set_status(req, PROBE_ANSWERS[i].status);
      httpd_resp_set_type(req, "text/html");
      httpd_resp_sendstr(req, PROBE_ANSWERS[i].body);
      return true;
    }
  }

  // Anything else: send the client to the real server once its DNS cache expired
  size_t location_len = strlen(host) + strlen(req->uri) + 8;
  char *location = (char *)malloc(location_len);
  if (!location)
    return false;
  snprintf(location, location_len, "http://%s%s", host, req->uri);
  httpd_resp_set_status(req, "307 Temporary Redirect");
  httpd_resp_set_hdr(req, "Location", location);
  httpd_resp_send(req, NULL, 0);
  free(location);
  return true;
}

/**
 * Public uplink status page - where clients' connectivity checks lead
 * while the uplink has no internet access (no login needed)
 */
static esp_err_t portal_page_handler(httpd_req_t *req)
{
  httpd_resp_set_type(req, "text/html");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  httpd_resp_sendstr_chunk(req, html_page_head);
  send_status_html(req);
  httpd_resp_sendstr_chunk(req, "<div class='info' style='text-align:center'><a href='/'>Repeater settings</a></div>");
  send_build_info(req);
  httpd_resp_sendstr_chunk(req, "</body></html>");
  httpd_resp_sendstr_chunk(req, NULL);
  return ESP_OK;
}

/**
 * Root page handler - serves configuration form
 */
static esp_err_t root_handler(httpd_req_t *req)
{
  if (handle_portal_probe(req))
    return ESP_OK;
  if (!check_auth(req))
    return ESP_OK;

  httpd_resp_set_type(req, "text/html");
  send_config_html(req, &stored_config);
  return ESP_OK;
}

/**
 * Parse "a.b.c.d/prefix" into separate address and netmask strings.
 * A missing prefix means /32.
 */
static bool parse_cidr(const char *cidr, char *ip_out, size_t ip_len, char *mask_out, size_t mask_len)
{
  char ip[16];
  const char *slash = strchr(cidr, '/');
  size_t addr_len = slash ? (size_t)(slash - cidr) : strlen(cidr);
  if (addr_len == 0 || addr_len >= sizeof(ip))
    return false;
  memcpy(ip, cidr, addr_len);
  ip[addr_len] = '\0';

  ip4_addr_t addr;
  if (!ip4addr_aton(ip, &addr))
    return false;

  int prefix = 32;
  if (slash)
  {
    char *end;
    prefix = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' || prefix < 0 || prefix > 32)
      return false;
  }

  uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
  snprintf(ip_out, ip_len, "%s", ip);
  snprintf(mask_out, mask_len, "%u.%u.%u.%u",
           (unsigned)(mask >> 24) & 0xFF, (unsigned)(mask >> 16) & 0xFF,
           (unsigned)(mask >> 8) & 0xFF, (unsigned)mask & 0xFF);
  return true;
}

/**
 * Copy a form value into a fixed-size config field - false if it does not fit
 */
static bool copy_field(char *dst, size_t dst_size, const char *value)
{
  if (strlen(value) >= dst_size)
    return false;
  strlcpy(dst, value, dst_size);
  return true;
}

/**
 * Read a urlencoded POST body into buf (NUL terminated)
 */
static bool read_post_body(httpd_req_t *req, char *buf, size_t buf_len)
{
  if (req->content_len >= buf_len)
    return false;

  size_t received = 0;
  while (received < req->content_len)
  {
    int ret = httpd_req_recv(req, buf + received, req->content_len - received);
    if (ret == HTTPD_SOCK_ERR_TIMEOUT)
      continue;
    if (ret <= 0)
      return false;
    received += ret;
  }
  buf[received] = '\0';
  return true;
}

/**
 * Save configuration handler - processes form submission via POST
 */
static esp_err_t save_handler(httpd_req_t *req)
{
  if (!check_auth(req))
    return ESP_OK;
  if (!is_same_origin(req))
  {
    httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Cross-site request blocked");
    return ESP_FAIL;
  }

  char *body = (char *)malloc(FORM_BODY_MAX);
  if (!body)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
    return ESP_FAIL;
  }

  if (!read_post_body(req, body, FORM_BODY_MAX))
  {
    free(body);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or too large form data");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG_MAIN, "Received config form");

  // Parse form fields - start with existing config to preserve passwords if left blank
  repeater_config_t new_config = stored_config;
  const char *error = NULL;

  if (!parse_query_param(body, "sta_ssid", new_config.sta_ssid, sizeof(new_config.sta_ssid)))
  {
    error = "Missing sta_ssid";
  }

  // Parse password, but only update if not empty; "-" removes it (open network)
  char temp_pass[64] = {0};
  if (!error && parse_query_param(body, "sta_pass", temp_pass, sizeof(temp_pass)) && strlen(temp_pass) > 0)
  {
    if (strcmp(temp_pass, "-") == 0)
      memset(new_config.sta_password, 0, sizeof(new_config.sta_password));
    else
      strncpy(new_config.sta_password, temp_pass, sizeof(new_config.sta_password));
  }

  // More networks: empty name removes one; password blank keeps it, "-" removes it
  for (int i = 0; !error && i < 4; i++)
  {
    char field[8];
    snprintf(field, sizeof(field), "ssid%d", i + 2);
    if (!parse_query_param(body, field, new_config.extra_ssid[i], sizeof(new_config.extra_ssid[i])))
      continue; // not in the form - keep
    snprintf(field, sizeof(field), "pass%d", i + 2);
    memset(temp_pass, 0, sizeof(temp_pass));
    if (new_config.extra_ssid[i][0] == '\0' ||
        (parse_query_param(body, field, temp_pass, sizeof(temp_pass)) && strcmp(temp_pass, "-") == 0))
      memset(new_config.extra_password[i], 0, sizeof(new_config.extra_password[i]));
    else if (strlen(temp_pass) > 0)
      strlcpy(new_config.extra_password[i], temp_pass, sizeof(new_config.extra_password[i]));
  }

  if (!error && !parse_query_param(body, "ap_ssid", new_config.ap_ssid, sizeof(new_config.ap_ssid)))
  {
    error = "Missing ap_ssid";
  }

  // Parse AP password, but only update if not empty (unless it was previously empty)
  memset(temp_pass, 0, sizeof(temp_pass));
  if (!error && parse_query_param(body, "ap_pass", temp_pass, sizeof(temp_pass)))
  {
    // If new password provided, validate it
    if (strlen(temp_pass) > 0)
    {
      if (strlen(temp_pass) < 8)
      {
        error = "AP password must be at least 8 characters or empty";
      }
      strncpy(new_config.ap_password, temp_pass, sizeof(new_config.ap_password));
    }
    // If empty and user explicitly wants open network, clear password
    else if (strlen(stored_config.ap_password) == 0)
    {
      memset(new_config.ap_password, 0, sizeof(new_config.ap_password));
    }
    // Otherwise keep existing password
  }

  /* WireGuard - checkbox is only present in the form data when checked */
  char temp[96] = {0};
  new_config.wg_enabled = parse_query_param(body, "wg_en", temp, sizeof(temp));
  parse_query_param(body, "wg_addr", new_config.wg_address, sizeof(new_config.wg_address));
  parse_query_param(body, "wg_host", new_config.wg_endpoint, sizeof(new_config.wg_endpoint));
  parse_query_param(body, "wg_dns", new_config.wg_dns, sizeof(new_config.wg_dns));
  new_config.wg_kill_switch = parse_query_param(body, "wg_kill", temp, sizeof(temp));

  // Keys are read in full so that a too long key is rejected instead of truncated
  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_peer", temp, sizeof(temp)) &&
      !copy_field(new_config.wg_peer_public_key, sizeof(new_config.wg_peer_public_key), temp))
    error = "WireGuard peer public key must be a 44 character base64 key";

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_priv", temp, sizeof(temp)) && strlen(temp) > 0 &&
      !copy_field(new_config.wg_private_key, sizeof(new_config.wg_private_key), temp))
    error = "WireGuard private key must be a 44 character base64 key";

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_psk", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    if (strcmp(temp, "-") == 0)
      memset(new_config.wg_preshared_key, 0, sizeof(new_config.wg_preshared_key));
    else if (!copy_field(new_config.wg_preshared_key, sizeof(new_config.wg_preshared_key), temp))
      error = "WireGuard preshared key must be a 44 character base64 key";
  }

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_port", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    int port = atoi(temp);
    if (port < 1 || port > 65535)
      error = "WireGuard port must be 1-65535";
    new_config.wg_port = (uint16_t)port;
  }

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_ka", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    int keepalive = atoi(temp);
    // Keepalive keeps the session alive while the tunnel is not the default route
    if (keepalive < 1 || keepalive > 65535)
      error = "WireGuard keepalive must be 1-65535";
    new_config.wg_keepalive = (uint16_t)keepalive;
  }

  /* Device */
  new_config.portal_redirect = parse_query_param(body, "portal_redir", temp, sizeof(temp));
  new_config.eco_mode = parse_query_param(body, "eco", temp, sizeof(temp));
  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "tx_pwr", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    int dbm = atoi(temp);
    if (dbm != 0 && (dbm < 2 || dbm > 20))
      error = "WiFi transmit power must be 2-20 dBm";
    new_config.tx_power = (uint8_t)dbm;
  }
  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "admin_pass", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    if (strlen(temp) < ADMIN_PASSWORD_MIN_LEN)
      error = "Admin password must be at least 8 characters";
    else if (!copy_field(new_config.admin_password, sizeof(new_config.admin_password), temp))
      error = "Admin password must be at most 63 characters";
  }

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "disp_off", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    int timeout = atoi(temp);
    if (timeout < 0 || timeout > 65535)
      error = "Screen timeout must be 0-65535 seconds";
    new_config.display_timeout = (uint16_t)timeout;
  }

  free(body);

  if (!error && strlen(new_config.admin_password) == 0)
    error = "Set an admin password for the web panel (Device section)";

  if (!error && new_config.wg_enabled)
  {
    char ip[16], mask[16];
    ip4_addr_t dns;
    if (strlen(new_config.wg_private_key) != WG_KEY_B64_LEN)
      error = "WireGuard private key must be a 44 character base64 key";
    else if (strlen(new_config.wg_peer_public_key) != WG_KEY_B64_LEN)
      error = "WireGuard peer public key must be a 44 character base64 key";
    else if (strlen(new_config.wg_preshared_key) != 0 && strlen(new_config.wg_preshared_key) != WG_KEY_B64_LEN)
      error = "WireGuard preshared key must be a 44 character base64 key";
    else if (!parse_cidr(new_config.wg_address, ip, sizeof(ip), mask, sizeof(mask)))
      error = "WireGuard address must look like 10.6.0.2/32";
    else if (strlen(new_config.wg_endpoint) == 0)
      error = "WireGuard endpoint is required";
    else if (strlen(new_config.wg_dns) > 0 && !ip4addr_aton(new_config.wg_dns, &dns))
      error = "DNS must be an IPv4 address";
  }

  if (error)
  {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error);
    return ESP_FAIL;
  }

  new_config.configured = true;

  ESP_LOGI(TAG_MAIN, "New configuration:");
  ESP_LOGI(TAG_MAIN, "  Uplink SSID: %s", new_config.sta_ssid);
  ESP_LOGI(TAG_MAIN, "  AP SSID: %s", new_config.ap_ssid);
  ESP_LOGI(TAG_MAIN, "  AP Password: %s", strlen(new_config.ap_password) > 0 ? "***" : "(open)");
  ESP_LOGI(TAG_MAIN, "  WireGuard: %s", new_config.wg_enabled ? new_config.wg_endpoint : "disabled");

  // Save configuration
  esp_err_t err = save_wifi_config(&new_config);
  if (err != ESP_OK)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save configuration");
    return ESP_FAIL;
  }

  // Send success page
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, html_success_page, HTTPD_RESP_USE_STRLEN);

  // Schedule restart
  ESP_LOGI(TAG_MAIN, "Configuration saved, restarting in 3 seconds...");
  vTaskDelay(pdMS_TO_TICKS(3000));
  esp_restart();

  return ESP_OK;
}

/**
 * Send a JSON string literal (with quotes), escaping special characters
 */
static void send_json_string(httpd_req_t *req, const char *src)
{
  char buf[80];
  size_t pos = 0;
  buf[pos++] = '"';
  while (*src)
  {
    unsigned char c = (unsigned char)*src++;
    if (pos + 7 >= sizeof(buf))
    {
      httpd_resp_send_chunk(req, buf, pos);
      pos = 0;
    }
    if (c == '"' || c == '\\')
    {
      buf[pos++] = '\\';
      buf[pos++] = c;
    }
    else if (c < 0x20)
    {
      pos += snprintf(buf + pos, sizeof(buf) - pos, "\\u%04x", c);
    }
    else
    {
      buf[pos++] = c;
    }
  }
  buf[pos++] = '"';
  httpd_resp_send_chunk(req, buf, pos);
}

#define WIFI_SCAN_MAX_APS 20

/**
 * WiFi scan handler - returns nearby networks as JSON
 */
/**
 * Scan for networks. Returns the records (sorted by RSSI, free() them) or
 * NULL with err set.
 */
static wifi_ap_record_t *scan_networks(uint16_t *count, esp_err_t *err_out)
{
  wifi_scan_config_t scan_config = {};
  scan_config.show_hidden = false;

  // A connection attempt in progress blocks scanning - pause reconnecting meanwhile
  bool pause_reconnect = reconnect_timer != NULL && !sta_connected;
  if (pause_reconnect)
  {
    scan_in_progress = true;
    esp_timer_stop(reconnect_timer);
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  ESP_LOGI(TAG_STA, "Scanning for networks...");
  esp_err_t err = esp_wifi_scan_start(&scan_config, true);

  if (pause_reconnect)
  {
    scan_in_progress = false;
    reconnect_delay_ms = WIFI_RECONNECT_MIN_MS;
    schedule_reconnect();
  }

  *err_out = err;
  if (err != ESP_OK)
  {
    // e.g. ESP_ERR_WIFI_STATE while the station is busy connecting
    ESP_LOGW(TAG_STA, "Scan failed: %s", esp_err_to_name(err));
    return NULL;
  }

  *count = WIFI_SCAN_MAX_APS;
  wifi_ap_record_t *records = (wifi_ap_record_t *)calloc(WIFI_SCAN_MAX_APS, sizeof(wifi_ap_record_t));
  if (!records)
  {
    esp_wifi_clear_ap_list();
    *err_out = ESP_ERR_NO_MEM;
    return NULL;
  }
  esp_wifi_scan_get_ap_records(count, records);
  ESP_LOGI(TAG_STA, "Scan found %d networks", *count);
  return records;
}

static esp_err_t scan_handler(httpd_req_t *req)
{
  if (!check_auth(req))
    return ESP_OK;

  uint16_t count = 0;
  esp_err_t err = ESP_OK;
  wifi_ap_record_t *records = scan_networks(&count, &err);
  if (!records)
  {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, esp_err_to_name(err));
    return ESP_OK;
  }

  // Records are sorted by RSSI; list each SSID once (strongest AP)
  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr_chunk(req, "[");
  bool first = true;
  for (int i = 0; i < count; i++)
  {
    const char *ssid = (const char *)records[i].ssid;
    if (ssid[0] == '\0')
      continue;

    bool duplicate = false;
    for (int j = 0; j < i && !duplicate; j++)
      duplicate = strcmp(ssid, (const char *)records[j].ssid) == 0;
    if (duplicate)
      continue;

    char fields[64];
    httpd_resp_sendstr_chunk(req, first ? "{\"ssid\":" : ",{\"ssid\":");
    send_json_string(req, ssid);
    snprintf(fields, sizeof(fields), ",\"rssi\":%d,\"ch\":%d,\"auth\":%s}",
             records[i].rssi, records[i].primary,
             (records[i].authmode == WIFI_AUTH_OPEN || records[i].authmode == WIFI_AUTH_OWE) ? "false" : "true");
    httpd_resp_sendstr_chunk(req, fields);
    first = false;
  }
  httpd_resp_sendstr_chunk(req, "]");
  httpd_resp_sendstr_chunk(req, NULL);

  free(records);
  return ESP_OK;
}

/* printf into the response (chunked) */
static void debug_printf(httpd_req_t *req, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void debug_printf(httpd_req_t *req, const char *fmt, ...)
{
  char line[192];
  va_list args;
  va_start(args, fmt);
  vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);
  httpd_resp_sendstr_chunk(req, line);
}

static const char *uplink_state_name(uplink_state_t state)
{
  switch (state)
  {
  case UPLINK_CHECKING:
    return "checking";
  case UPLINK_PORTAL:
    return "captive portal (login required)";
  case UPLINK_NO_INTERNET:
    return "connected, no internet";
  case UPLINK_ONLINE:
    return "online";
  default:
    return "offline (not connected)";
  }
}

/* "12s ago" / "never" for a WireGuard millis timestamp */
static const char *wg_age(char *buf, size_t len, uint32_t now, uint32_t then)
{
  if (then == 0)
    return "never";
  snprintf(buf, len, "%lus ago", (unsigned long)((now - then) / 1000));
  return buf;
}

static void send_wireguard_debug(httpd_req_t *req, int64_t now_us)
{
  debug_printf(req, "\n== WireGuard ==\nEndpoint: %s:%u (UDP)\nInterface address: %s, keepalive %us\n",
               stored_config.wg_endpoint, (unsigned)stored_config.wg_port, stored_config.wg_address,
               (unsigned)stored_config.wg_keepalive);
  debug_printf(req, "Stage: %s\n", wg_status);
  debug_printf(req, "Kill switch: %s, %lu packets blocked\n",
               !stored_config.wg_kill_switch ? "off" : kill_switch_active() ? "BLOCKING client traffic" : "on (not blocking)",
               (unsigned long)kill_switch_drops);

  time_t t = time(NULL);
  struct tm utc;
  gmtime_r(&t, &utc);
  char clock[32];
  strftime(clock, sizeof(clock), "%Y-%m-%d %H:%M:%S", &utc);
  debug_printf(req, "Clock: %s UTC%s\n", clock, t < 1700000000 ? " (not synchronized)" : "");

  if (!wg_connected)
    return;

  int64_t running_s = (now_us - wg_connect_us) / 1000000;
  debug_printf(req, "Started: %llds ago\n", (long long)running_s);

  wg_peer_snapshot_t snap = {};
  if (esp_netif_tcpip_exec(wg_snapshot_cb, &snap) != ESP_OK || !snap.valid)
  {
    httpd_resp_sendstr_chunk(req, "Peer: not set up\n");
    return;
  }

  char a[24], b[24];
  debug_printf(req, "Resolved endpoint: %s:%u\n", ipaddr_ntoa_r(&snap.endpoint_ip, a, sizeof(a)), (unsigned)snap.endpoint_port);
  // The library sets the peer address to the endpoint already when connecting
  if (snap.last_rx != 0 || snap.latest_handshake != 0)
    debug_printf(req, "Answers from: %s:%u\n", ipaddr_ntoa_r(&snap.seen_ip, b, sizeof(b)), (unsigned)snap.seen_port);
  else
    httpd_resp_sendstr_chunk(req, "Answers from: none yet\n");
  debug_printf(req, "Last handshake: %s\n", wg_age(a, sizeof(a), snap.now, snap.latest_handshake));
  debug_printf(req, "Last handshake attempt sent: %s\n", wg_age(a, sizeof(a), snap.now, snap.last_initiation_tx));
  debug_printf(req, "Last packet received: %s, sent: %s\n", wg_age(a, sizeof(a), snap.now, snap.last_rx),
               wg_age(b, sizeof(b), snap.now, snap.last_tx));

  if (snap.latest_handshake == 0 && snap.last_rx == 0 && running_s > 30)
    debug_printf(req, "\n>> No answer from the server. UDP port %u is probably blocked by this network - "
                      "try UDP 443, 53, 123 or 4500 on the server. Otherwise check the endpoint, "
                      "the server's firewall and the keys.\n",
                 (unsigned)stored_config.wg_port);
}

/**
 * Debug page (plain text, easy to copy): uplink connection details, the
 * last connectivity check, optionally a WiFi scan (?scan=1) and the recent
 * log output. ?check=1 runs the connectivity check right away.
 */
static esp_err_t debug_handler(httpd_req_t *req)
{
  if (!check_auth(req))
    return ESP_OK;

  char query[32] = {0}, value[4] = {0};
  httpd_req_get_url_query_str(req, query, sizeof(query));
  bool scan = httpd_query_key_value(query, "scan", value, sizeof(value)) == ESP_OK;
  if (httpd_query_key_value(query, "check", value, sizeof(value)) == ESP_OK && status_task_handle)
    xTaskNotifyGive(status_task_handle);

  httpd_resp_set_type(req, "text/plain; charset=utf-8");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");

  const esp_app_desc_t *app = esp_app_get_description();
#ifdef FIRMWARE_VERSION
  const char *version = FIRMWARE_VERSION;
#else
  const char *version = app->version;
#endif
  int64_t now = esp_timer_get_time();
  debug_printf(req, "CardRepeater debug - build %s (%s %s, ESP-IDF %s)\n", version, app->date, app->time, app->idf_ver);
  debug_printf(req, "Uptime: %llds, free heap: %lu bytes (min %lu)\n\n", (long long)(now / 1000000),
               (unsigned long)esp_get_free_heap_size(), (unsigned long)esp_get_minimum_free_heap_size());

  /* Uplink connection */
  httpd_resp_sendstr_chunk(req, "== Uplink WiFi ==\nSaved networks (* = current):\n");
  for (int i = 0; i < UPLINK_NETWORKS; i++)
    if (network_ssid(i)[0] != '\0')
      debug_printf(req, " %c \"%s\", password: %s\n", i == active_network ? '*' : ' ', network_ssid(i),
                   strlen(network_password(i)) > 0 ? "yes" : "no (open network)");
  debug_printf(req, "Connect mode: %s\n",
               strlen(network_password(active_network)) == 0 ? "open, any security"
               : sta_open_fallback                    ? "without password (open network fallback)"
                                                      : "with password, WPA2 or better");
  debug_printf(req, "Connected: %s\n", sta_connected ? "yes" : "no");
  if (sta_connected)
    debug_printf(req, "Connected for: %llds\n", (long long)((now - connected_since_us) / 1000000));
  debug_printf(req, "Disconnects: %lu", (unsigned long)disconnect_count);
  if (disconnect_count > 0)
    debug_printf(req, ", last: reason %u (%s) %llds ago", (unsigned)last_disconnect_reason,
                 disconnect_reason_text(last_disconnect_reason), (long long)((now - last_disconnect_us) / 1000000));
  httpd_resp_sendstr_chunk(req, "\n");

  wifi_ap_record_t ap_info;
  if (sta_connected && esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    debug_printf(req, "AP: " MACSTR ", channel %d, RSSI %d dBm, security %s\n", MAC2STR(ap_info.bssid),
                 ap_info.primary, ap_info.rssi, authmode_name(ap_info.authmode));

  esp_netif_ip_info_t ip;
  if (sta_netif && esp_netif_get_ip_info(sta_netif, &ip) == ESP_OK)
    debug_printf(req, "IP: " IPSTR "/" IPSTR ", gateway " IPSTR "\n", IP2STR(&ip.ip), IP2STR(&ip.netmask), IP2STR(&ip.gw));
  esp_netif_dns_info_t dns = {};
  if (sta_netif && esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
    debug_printf(req, "DNS: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));

  /* Internet */
  debug_printf(req, "\n== Internet ==\nState: %s\n", uplink_state_name(uplink_state));
  debug_printf(req, "Last check: %s\n", strlen(probe_info) > 0 ? probe_info : "-");
  if (strlen(portal_url) > 0)
    debug_printf(req, "Login page: %s\n", portal_url);
  debug_printf(req, "Portal redirect for clients: %s\n", stored_config.portal_redirect ? "on" : "off");

  /* Battery */
  int8_t tx_quarter_dbm = 0;
  esp_wifi_get_max_tx_power(&tx_quarter_dbm);
  debug_printf(req, "\n== Power ==\nWiFi transmit power: %d.%02d dBm%s\nEco mode: %s\n", tx_quarter_dbm / 4,
               (tx_quarter_dbm % 4) * 25, stored_config.tx_power == 0 ? " (maximum)" : "",
               stored_config.eco_mode ? "on (CPU 80-160 MHz)" : "off (CPU 240 MHz)");

  /* Access point */
  debug_printf(req, "\n== Access point ==\nSSID: \"%s\", address %s, channel %d, clients %d\n",
               stored_config.ap_ssid, ap_ip_str, WIFI_AP_CHANNEL, ap_client_count);

  /* WireGuard */
  if (stored_config.wg_enabled)
    send_wireguard_debug(req, now);

  /* Scan */
  if (scan)
  {
    httpd_resp_sendstr_chunk(req, "\n== WiFi scan (2.4 GHz only) ==\n");
    uint16_t count = 0;
    esp_err_t err = ESP_OK;
    wifi_ap_record_t *records = scan_networks(&count, &err);
    if (!records)
    {
      debug_printf(req, "Scan failed: %s\n", esp_err_to_name(err));
    }
    else
    {
      bool found = false;
      for (int i = 0; i < count; i++)
      {
        bool match = false;
        for (int n = 0; n < UPLINK_NETWORKS && !match; n++)
          match = network_ssid(n)[0] != '\0' && strcmp((const char *)records[i].ssid, network_ssid(n)) == 0;
        found |= match;
        debug_printf(req, "%s %-32s ch %2d %4d dBm  %s\n", match ? ">>" : "  ",
                     records[i].ssid[0] ? (const char *)records[i].ssid : "(hidden)", records[i].primary,
                     records[i].rssi, authmode_name(records[i].authmode));
      }
      if (!found)
        httpd_resp_sendstr_chunk(req, "No saved network found - check the names, the distance, or whether they are 5 GHz only\n");
      free(records);
    }
  }

  /* Recent log */
  httpd_resp_sendstr_chunk(req, "\n== Log ==\n");
  char *copy = (char *)malloc(DEBUG_LOG_SIZE);
  if (copy)
  {
    taskENTER_CRITICAL(&debug_log_lock);
    size_t len = debug_log_wrapped ? DEBUG_LOG_SIZE : debug_log_head;
    size_t start = debug_log_wrapped ? debug_log_head : 0;
    memcpy(copy, debug_log + start, len - start);
    memcpy(copy + (len - start), debug_log, start);
    taskEXIT_CRITICAL(&debug_log_lock);
    httpd_resp_send_chunk(req, copy, len);
    free(copy);
  }
  httpd_resp_sendstr_chunk(req, NULL);
  return ESP_OK;
}

/**
 * Catch-all handler - redirects to the config page.
 * Together with the DNS server in setup mode this makes phones and laptops
 * open the configuration page automatically (captive portal).
 */
static esp_err_t captive_redirect_handler(httpd_req_t *req)
{
  if (handle_portal_probe(req))
    return ESP_OK;

  char location[32];
  snprintf(location, sizeof(location), "http://%s/", ap_ip_str);
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", location);
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

/**
 * Start web server
 */
static httpd_handle_t start_webserver(void)
{
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.stack_size = WEB_SERVER_STACK_SIZE;
  config.uri_match_fn = httpd_uri_match_wildcard;
  config.lru_purge_enable = true; // OS captive portal probes open many connections

  ESP_LOGI(TAG_MAIN, "Starting web server on port %d", config.server_port);

  if (httpd_start(&web_server, &config) == ESP_OK)
  {
    // Register URI handlers
    httpd_uri_t root = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &root);

    httpd_uri_t save = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = save_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &save);

    httpd_uri_t scan = {
        .uri = "/scan",
        .method = HTTP_GET,
        .handler = scan_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &scan);

    httpd_uri_t debug = {
        .uri = "/debug",
        .method = HTTP_GET,
        .handler = debug_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &debug);

    httpd_uri_t portal = {
        .uri = "/portal",
        .method = HTTP_GET,
        .handler = portal_page_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &portal);

    // Must be registered last - matches everything
    httpd_uri_t captive = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = captive_redirect_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &captive);

    ESP_LOGI(TAG_MAIN, "✓ Web server started successfully");
    ESP_LOGI(TAG_MAIN, "  Access at: http://%s/", ap_ip_str);

    return web_server;
  }

  ESP_LOGE(TAG_MAIN, "✗ Failed to start web server");
  return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * DNS SERVERS
 * ═══════════════════════════════════════════════════════════════════ */

/* Host names operating systems use to detect captive portals */
static const char *const PORTAL_PROBE_HOSTS[] = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.appleiphonecell.com",
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "network-test.debian.org",
    "connectivity-check.ubuntu.com",
    "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com",
};

#define DNS_HEADER_LEN 12
#define DNS_ANSWER_LEN 16 // A record with a name pointer
#define DNS_PROXY_SLOTS 16
#define DNS_PROXY_TIMEOUT_MS 5000

/**
 * Parse a standard query (QR=0, OPCODE=0) with exactly one question.
 * Writes the lower case name and type; returns the length of the
 * question section end (offset) or -1.
 */
static int dns_parse_query(const uint8_t *buf, int len, char *name, size_t name_len, uint16_t *qtype)
{
  if (len < DNS_HEADER_LEN || (buf[2] & 0x80) || (buf[2] & 0x78) || buf[4] != 0 || buf[5] != 1)
    return -1;

  int pos = DNS_HEADER_LEN;
  size_t out = 0;
  while (pos < len && buf[pos] != 0)
  {
    int label = buf[pos];
    if ((label & 0xC0) || pos + 1 + label > len)
      return -1;
    if (out > 0 && out < name_len - 1)
      name[out++] = '.';
    for (int i = 0; i < label; i++)
      if (out < name_len - 1)
        name[out++] = (char)tolower(buf[pos + 1 + i]);
    pos += label + 1;
  }
  name[out] = '\0';
  pos++; // zero length root label
  if (pos + 4 > len)
    return -1;
  *qtype = (buf[pos] << 8) | buf[pos + 1];
  return pos + 4;
}

/**
 * Turn the query in buf into an answer in place. With an address (network
 * byte order) an A
 * record follows the question (buf needs DNS_ANSWER_LEN spare bytes),
 * otherwise the answer is empty. Returns the answer length.
 */
static int dns_build_answer(uint8_t *buf, int question_end, const uint32_t *addr, uint32_t ttl)
{
  buf[2] = 0x84 | (buf[2] & 0x01); // QR, AA, keep RD
  buf[3] = 0x80;                   // RA, NOERROR
  buf[6] = 0;
  buf[7] = addr ? 1 : 0;      // ANCOUNT
  memset(&buf[8], 0, 4);      // NSCOUNT, ARCOUNT - drops any EDNS record
  if (!addr)
    return question_end;

  const uint8_t record[12] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                              (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
                              0x00, 0x04};
  memcpy(&buf[question_end], record, sizeof(record));
  memcpy(&buf[question_end + 12], addr, 4);
  return question_end + DNS_ANSWER_LEN;
}

static int dns_open_server_socket(void)
{
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
  {
    ESP_LOGE(TAG_MAIN, "DNS: failed to create socket");
    return -1;
  }

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    ESP_LOGE(TAG_MAIN, "DNS: failed to bind port 53");
    close(sock);
    return -1;
  }
  return sock;
}

/**
 * Captive portal DNS server (setup mode only).
 * Answers every A query with the AP address so any hostname leads to the config page.
 */
static void captive_dns_task(void *pvParameters)
{
  int sock = dns_open_server_socket();
  if (sock < 0)
  {
    vTaskDelete(NULL);
    return;
  }

  esp_netif_ip_info_t ip_info;
  esp_netif_get_ip_info(ap_netif, &ip_info);
  ESP_LOGI(TAG_MAIN, "✓ Captive portal DNS started (all names -> " IPSTR ")", IP2STR(&ip_info.ip));

  uint8_t buf[512];
  char name[128];
  while (1)
  {
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int len = recvfrom(sock, buf, sizeof(buf) - DNS_ANSWER_LEN, 0, (struct sockaddr *)&client, &client_len);

    uint16_t qtype;
    int question_end = dns_parse_query(buf, len, name, sizeof(name), &qtype);
    if (question_end < 0)
      continue;

    bool answer = (qtype == 1 /* A */ || qtype == 255 /* ANY */);
    int resp_len = dns_build_answer(buf, question_end, answer ? &ip_info.ip.addr : NULL, 60);
    sendto(sock, buf, resp_len, 0, (struct sockaddr *)&client, client_len);
  }
}

static bool is_portal_probe_host(const char *name)
{
  for (size_t i = 0; i < sizeof(PORTAL_PROBE_HOSTS) / sizeof(PORTAL_PROBE_HOSTS[0]); i++)
    if (strcmp(name, PORTAL_PROBE_HOSTS[i]) == 0)
      return true;
  return false;
}

/**
 * DNS server the proxy forwards to: the VPN DNS while the tunnel carries
 * the traffic, otherwise the uplink's DNS server
 */
static bool dns_upstream_server(ip4_addr_t *server)
{
  if (stored_config.wg_enabled && wg_is_default && strlen(stored_config.wg_dns) > 0 &&
      ip4addr_aton(stored_config.wg_dns, server))
    return true;
  if (!sta_connected)
    return false;

  esp_netif_dns_info_t dns = {};
  if (esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK ||
      dns.ip.type != ESP_IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0)
    return false;

  // Never forward to ourselves
  esp_netif_ip_info_t ap_info;
  esp_netif_get_ip_info(ap_netif, &ap_info);
  if (dns.ip.u_addr.ip4.addr == ap_info.ip.addr)
    return false;

  server->addr = dns.ip.u_addr.ip4.addr;
  return true;
}

typedef struct
{
  bool used;
  uint16_t client_id;   // query ID chosen by the client
  uint16_t upstream_id; // query ID sent upstream
  struct sockaddr_in client;
  struct sockaddr_in server;
  TickType_t sent;
} dns_pending_t;

/**
 * DNS proxy for AP clients (normal mode, when portal redirect is enabled).
 *
 * Forwards queries to the upstream DNS server. While the uplink needs a
 * captive portal login, the host names operating systems use for their
 * connectivity checks resolve to this device instead, whose web server
 * redirects the check to the login page - clients then open the login
 * page on their own.
 */
static void dns_proxy_task(void *pvParameters)
{
  int sock = dns_open_server_socket();
  int upstream = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0 || upstream < 0)
  {
    ESP_LOGE(TAG_MAIN, "DNS proxy: no sockets");
    if (sock >= 0)
      close(sock);
    if (upstream >= 0)
      close(upstream);
    vTaskDelete(NULL);
    return;
  }
  ESP_LOGI(TAG_MAIN, "✓ DNS proxy started");

  static uint8_t buf[1500];
  static dns_pending_t pending[DNS_PROXY_SLOTS];
  char name[128];
  uint16_t next_id = (uint16_t)esp_random();

  while (1)
  {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    FD_SET(upstream, &fds);
    struct timeval tv = {1, 0};
    if (select((sock > upstream ? sock : upstream) + 1, &fds, NULL, NULL, &tv) <= 0)
      continue;

    /* Query from a client */
    if (FD_ISSET(sock, &fds))
    {
      struct sockaddr_in client;
      socklen_t client_len = sizeof(client);
      int len = recvfrom(sock, buf, sizeof(buf) - DNS_ANSWER_LEN, 0, (struct sockaddr *)&client, &client_len);

      // Only serve the AP subnet - no open resolver on the uplink side
      esp_netif_ip_info_t ap_info;
      esp_netif_get_ip_info(ap_netif, &ap_info);
      bool from_ap = ((client.sin_addr.s_addr ^ ap_info.ip.addr) & ap_info.netmask.addr) == 0;

      uint16_t qtype = 0;
      int question_end = (from_ap && len > 0) ? dns_parse_query(buf, len, name, sizeof(name), &qtype) : -1;
      ip4_addr_t server;

      if (!from_ap || len < DNS_HEADER_LEN)
      {
        // ignore
      }
      else if (question_end > 0 && intercept_portal_probes() && is_portal_probe_host(name))
      {
        // A record pointing to us, no IPv6 address - TTL 0 so the real address is used after login
        int resp_len = dns_build_answer(buf, question_end, qtype == 1 ? &ap_info.ip.addr : NULL, 0);
        sendto(sock, buf, resp_len, 0, (struct sockaddr *)&client, client_len);
        ESP_LOGD(TAG_MAIN, "DNS proxy: %s -> portal redirect", name);
      }
      else if (!kill_switch_active() && dns_upstream_server(&server)) // no DNS leak past the kill switch
      {
        // Reuse a free or timed out slot, else the oldest one
        TickType_t now = xTaskGetTickCount();
        dns_pending_t *slot = &pending[0];
        for (int i = 0; i < DNS_PROXY_SLOTS; i++)
        {
          if (!pending[i].used || (now - pending[i].sent) > pdMS_TO_TICKS(DNS_PROXY_TIMEOUT_MS))
          {
            slot = &pending[i];
            break;
          }
          if ((now - pending[i].sent) > (now - slot->sent))
            slot = &pending[i];
        }

        slot->used = true;
        slot->client_id = (buf[0] << 8) | buf[1];
        slot->upstream_id = next_id++;
        slot->client = client;
        slot->server = {};
        slot->server.sin_family = AF_INET;
        slot->server.sin_port = htons(53);
        slot->server.sin_addr.s_addr = server.addr;
        slot->sent = now;

        buf[0] = slot->upstream_id >> 8;
        buf[1] = slot->upstream_id & 0xFF;
        sendto(upstream, buf, len, 0, (struct sockaddr *)&slot->server, sizeof(slot->server));
      }
    }

    /* Answer from the upstream server */
    if (FD_ISSET(upstream, &fds))
    {
      struct sockaddr_in from;
      socklen_t from_len = sizeof(from);
      int len = recvfrom(upstream, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
      if (len < DNS_HEADER_LEN)
        continue;

      uint16_t id = (buf[0] << 8) | buf[1];
      for (int i = 0; i < DNS_PROXY_SLOTS; i++)
      {
        dns_pending_t *slot = &pending[i];
        if (slot->used && slot->upstream_id == id &&
            from.sin_addr.s_addr == slot->server.sin_addr.s_addr && from.sin_port == slot->server.sin_port)
        {
          buf[0] = slot->client_id >> 8;
          buf[1] = slot->client_id & 0xFF;
          sendto(sock, buf, len, 0, (struct sockaddr *)&slot->client, sizeof(slot->client));
          slot->used = false;
          break;
        }
      }
    }
  }
}

/**
 * Stop web server
 */
static void stop_webserver(httpd_handle_t server)
{
  if (server)
  {
    httpd_stop(server);
    ESP_LOGI(TAG_MAIN, "Web server stopped");
  }
}

/**
 * Draw signal strength bars (1-4 bars based on RSSI)
 */
static void draw_signal_bars(int x, int y, int rssi)
{
  // Calculate number of bars (1-4) based on RSSI
  int bars = 1;
  if (rssi > -70)
    bars = 4;
  else if (rssi > -80)
    bars = 3;
  else if (rssi > -90)
    bars = 2;

  uint16_t bar_color = TERM_GREEN; // Always bright green when active

  // Draw 4 bars with increasing height
  for (int i = 0; i < 4; i++)
  {
    int bar_height = 2 + (i * 2);                                 // Heights: 2, 4, 6, 8
    int bar_y = y + (8 - bar_height);                             // Align bottom
    uint16_t color = (i < bars) ? bar_color : RGB565(20, 40, 20); // Dark green if not active
    lcd_fill_rect(x + (i * 4), bar_y, 3, bar_height, color);
  }
}

/**
 * Draw a filled circle (using filled rectangle approximation)
 */
static void draw_circle(int x, int y, int radius, uint16_t color)
{
  for (int dy = -radius; dy <= radius; dy++)
  {
    for (int dx = -radius; dx <= radius; dx++)
    {
      if (dx * dx + dy * dy <= radius * radius)
      {
        if (x + dx >= 0 && x + dx < LCD_V_RES && y + dy >= 0 && y + dy < LCD_H_RES)
        {
          framebuffer[(y + dy) * LCD_V_RES + (x + dx)] = color;
        }
      }
    }
  }
}

/**
 * Draw the battery level (percentage and icon), right-aligned at right_x
 */
static void draw_battery(int right_x, int y, uint16_t bg_color)
{
  if (battery_mv < 0)
    return;

  int level = battery_percent();
  uint16_t color = level <= 15 ? RGB565(0, 0, 200) : TERM_GREEN; // red when low

  // 18x9 outline with a 2x5 terminal on the right
  int x = right_x - 20;
  lcd_fill_rect(x, y, 18, 9, color);
  lcd_fill_rect(x + 1, y + 1, 16, 7, bg_color);
  lcd_fill_rect(x + 18, y + 2, 2, 5, color);
  lcd_fill_rect(x + 2, y + 2, 14 * level / 100, 5, color);

  char text[12];
  snprintf(text, sizeof(text), "%d%%", level);
  lcd_draw_string(x - 4 - (int)strlen(text) * 8, y + 1, text, color, bg_color);
}

/**
 * Setup mode screen: how to reach the configuration page
 */
static void draw_setup_screen(void)
{
  lcd_fill_screen(TERM_BG);
  lcd_fill_rect(0, 0, 240, 18, TERM_GREEN_DARK);
  lcd_draw_string(40, 5, "SETUP MODE", TERM_GREEN, TERM_GREEN_DARK);
  draw_battery(236, 4, TERM_GREEN_DARK);

  lcd_draw_string(5, 30, "WiFi:", TERM_GREEN_DIM, TERM_BG);
  lcd_draw_string(5, 45, DEFAULT_CONFIG_AP_SSID, TERM_ACCENT, TERM_BG);

  lcd_draw_string(5, 65, "Config IP:", TERM_GREEN_DIM, TERM_BG);
  lcd_draw_string(5, 80, ap_ip_str, TERM_GREEN, TERM_BG);

  lcd_draw_string(5, 100, "Open browser and", TERM_GREEN_DIM, TERM_BG);
  lcd_draw_string(5, 113, "visit IP above", TERM_GREEN_DIM, TERM_BG);
}

/**
 * Status screen with beautiful visual UI
 */
static void draw_status_screen(void)
{
  // Clear screen with pure black background (terminal style)
  lcd_fill_screen(TERM_BG);

  // ═══════════════════════════════════════════════════════════
  // HEADER with Title - Terminal style
  // ═══════════════════════════════════════════════════════════
  lcd_fill_rect(0, 0, 240, 16, TERM_GREEN_DARK);
  lcd_draw_string(6, 4, "Card Wifi Repeater", TERM_GREEN, TERM_GREEN_DARK);
  draw_battery(236, 3, TERM_GREEN_DARK);

  // ═══════════════════════════════════════════════════════════
  // UPLINK SECTION (Box 1)
  // ═══════════════════════════════════════════════════════════
  int uplink_y = 18;

  // Draw uplink box background with green border
  lcd_fill_rect(2, uplink_y, 236, 42, TERM_BG);
  // Green border
  lcd_fill_rect(2, uplink_y, 236, 1, TERM_GREEN_DIM);      // Top
  lcd_fill_rect(2, uplink_y + 41, 236, 1, TERM_GREEN_DIM); // Bottom
  lcd_fill_rect(2, uplink_y, 1, 42, TERM_GREEN_DIM);       // Left
  lcd_fill_rect(237, uplink_y, 1, 42, TERM_GREEN_DIM);     // Right

  // Uplink label
  lcd_draw_string(6, uplink_y + 3, "UPLINK", TERM_GREEN, TERM_BG);

  if (sta_connected)
  {
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
      // WiFi name in bright green
      lcd_draw_string(6, uplink_y + 14, network_ssid(active_network), TERM_ACCENT, TERM_BG);

      // Signal strength bars
      draw_signal_bars(6, uplink_y + 27, ap_info.rssi);

      // RSSI value
      char rssi_str[16];
      snprintf(rssi_str, sizeof(rssi_str), "%ddBm", ap_info.rssi);
      lcd_draw_string(26, uplink_y + 27, rssi_str, TERM_GREEN_DIM, TERM_BG);
    }

    // Internet status indicator (circle) - Green when internet is actually working
    if (uplink_state == UPLINK_ONLINE)
    {
      lcd_draw_string(200, uplink_y + 3, "NET", TERM_GREEN_DIM, TERM_BG);
      draw_circle(228, uplink_y + 7, 5, TERM_GREEN); // Bright green = Internet confirmed
    }
    else if (uplink_state == UPLINK_PORTAL)
    {
      lcd_draw_string(160, uplink_y + 3, "LOGIN", TERM_ACCENT, TERM_BG);
      draw_circle(228, uplink_y + 7, 5, RGB565(0, 165, 255)); // Orange = Captive portal, login required
    }
    else if (uplink_state == UPLINK_NO_INTERNET)
    {
      lcd_draw_string(152, uplink_y + 3, "NO NET", TERM_GREEN_DIM, TERM_BG);
      draw_circle(228, uplink_y + 7, 5, RGB565(0, 0, 200)); // Red = Connected, but no internet
    }
    else if (uplink_state == UPLINK_CHECKING)
    {
      lcd_draw_string(203, uplink_y + 3, "...", TERM_GREEN_DIM, TERM_BG);
      draw_circle(228, uplink_y + 7, 5, RGB565(0, 200, 200)); // Yellow = Connected, checking...
    }
    else
    {
      draw_circle(228, uplink_y + 7, 5, RGB565(0, 0, 200)); // Red = No internet
    }

    // WireGuard tunnel status
    if (stored_config.wg_enabled)
    {
      const char *vpn_str = wg_is_default ? "VPN:ON" : kill_switch_active() ? "VPN:BLK" : (wg_peer_up ? "VPN:RDY" : "VPN:..");
      lcd_draw_string(176, uplink_y + 27, vpn_str, wg_is_default ? TERM_GREEN : TERM_GREEN_DIM, TERM_BG);
    }
    else if (wg_configured())
    {
      lcd_draw_string(168, uplink_y + 27, "VPN:OFF", TERM_GREEN_DIM, TERM_BG); // V switches it on
    }
  }
  else
  {
    // Disconnected state - network name and why the last attempt failed
    lcd_draw_string(6, uplink_y + 14, network_ssid(active_network), TERM_GREEN_DIM, TERM_BG);
    char reason[32];
    if (last_disconnect_reason == 0)
      snprintf(reason, sizeof(reason), "Searching...");
    else
      snprintf(reason, sizeof(reason), "%s (%u)", disconnect_reason_text(last_disconnect_reason),
               (unsigned)last_disconnect_reason);
    lcd_draw_string(6, uplink_y + 27, reason, TERM_ACCENT, TERM_BG);
    draw_circle(228, uplink_y + 7, 5, RGB565(0, 0, 200)); // Red = Disconnected
  }

  // ═══════════════════════════════════════════════════════════
  // ACCESS POINT SECTION (Box 2)
  // ═══════════════════════════════════════════════════════════
  int ap_y = 62;

  // Draw AP box background with green border
  lcd_fill_rect(2, ap_y, 236, 42, TERM_BG);
  // Green border
  lcd_fill_rect(2, ap_y, 236, 1, TERM_GREEN_DIM);      // Top
  lcd_fill_rect(2, ap_y + 41, 236, 1, TERM_GREEN_DIM); // Bottom
  lcd_fill_rect(2, ap_y, 1, 42, TERM_GREEN_DIM);       // Left
  lcd_fill_rect(237, ap_y, 1, 42, TERM_GREEN_DIM);     // Right

  // AP label
  lcd_draw_string(6, ap_y + 3, "ACCESS POINT", TERM_GREEN, TERM_BG);

  // AP SSID
  lcd_draw_string(6, ap_y + 14, stored_config.ap_ssid, TERM_ACCENT, TERM_BG);

  // Password status
  if (strlen(stored_config.ap_password) > 0)
  {
    lcd_draw_string(6, ap_y + 25, "Secured", TERM_GREEN_DIM, TERM_BG);
  }
  else
  {
    lcd_draw_string(6, ap_y + 25, "Open", TERM_GREEN_DIM, TERM_BG);
  }

  // Power settings (P / E keys), right-aligned
  char power_str[16];
  if (stored_config.tx_power == 0)
    snprintf(power_str, sizeof(power_str), "%sTX:MAX", stored_config.eco_mode ? "ECO " : "");
  else
    snprintf(power_str, sizeof(power_str), "%sTX:%u", stored_config.eco_mode ? "ECO " : "", (unsigned)stored_config.tx_power);
  lcd_draw_string(232 - (int)strlen(power_str) * 8, ap_y + 25, power_str, TERM_GREEN_DIM, TERM_BG);

  // Client count (bright green to match theme)
  char clients_str[24];
  snprintf(clients_str, sizeof(clients_str), "CL:%d", ap_client_count);
  lcd_draw_string(200, ap_y + 3, clients_str, TERM_GREEN, TERM_BG);

  // ═══════════════════════════════════════════════════════════
  // CONFIG IP SECTION (Box 3) - Only if no clients
  // ═══════════════════════════════════════════════════════════
  if (ap_client_count == 0)
  {
    int config_y = 106;

    // Draw config box background with green border
    lcd_fill_rect(2, config_y, 236, 18, TERM_BG);
    // Green border
    lcd_fill_rect(2, config_y, 236, 1, TERM_GREEN_DIM);      // Top
    lcd_fill_rect(2, config_y + 17, 236, 1, TERM_GREEN_DIM); // Bottom
    lcd_fill_rect(2, config_y, 1, 18, TERM_GREEN_DIM);       // Left
    lcd_fill_rect(237, config_y, 1, 18, TERM_GREEN_DIM);     // Right

    lcd_draw_string(6, config_y + 5, "Config:", TERM_GREEN_DIM, TERM_BG);
    lcd_draw_string(64, config_y + 5, ap_ip_str, TERM_GREEN, TERM_BG);
  }
}

/**
 * Redraw the screen for the current mode (skipped while the screen is off)
 */
static void display_update_status(void)
{
  if (!framebuffer)
    return;

  xSemaphoreTakeRecursive(display_mutex, portMAX_DELAY);
  if (display_on && !reset_screen_shown)
  {
    if (config_mode)
      draw_setup_screen();
    else
      draw_status_screen();
    lcd_flush();
  }
  xSemaphoreGiveRecursive(display_mutex);
}

/**
 * User activity or an important event: restart the screen timeout,
 * turn the screen on and redraw it
 */
static void display_wake(void)
{
  xSemaphoreTakeRecursive(display_mutex, portMAX_DELAY);
  last_activity_tick = xTaskGetTickCount();
  bool was_off = !display_on;
  display_on = true;
  display_update_status(); // draw before the backlight comes on
  if (was_off)
    gpio_set_level((gpio_num_t)LCD_BL_PIN, 1);
  xSemaphoreGiveRecursive(display_mutex);
}

/**
 * Turn the screen off after `timeout` ticks without activity - no redraws until display_wake()
 */
static void display_sleep_if_idle(TickType_t timeout)
{
  xSemaphoreTakeRecursive(display_mutex, portMAX_DELAY);
  if (display_on && !reset_screen_shown && xTaskGetTickCount() - last_activity_tick >= timeout)
  {
    display_on = false;
    gpio_set_level((gpio_num_t)LCD_BL_PIN, 0);
    ESP_LOGI(TAG_MAIN, "Screen off (press G0 to wake)");
  }
  xSemaphoreGiveRecursive(display_mutex);
}

/* ═══════════════════════════════════════════════════════════════════
 * G0 BUTTON, SCREEN TIMEOUT AND FACTORY RESET
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Factory reset screen - owns the display until the reset is cancelled
 */
static void draw_reset_screen(const char *line1, const char *line2)
{
  xSemaphoreTakeRecursive(display_mutex, portMAX_DELAY);
  reset_screen_shown = true;
  display_on = true;
  lcd_fill_screen(TERM_BG);
  lcd_fill_rect(0, 0, 240, 16, TERM_GREEN_DARK);
  lcd_draw_string(68, 4, "FACTORY RESET", TERM_GREEN, TERM_GREEN_DARK);
  lcd_draw_string(8, 50, line1, TERM_ACCENT, TERM_BG);
  lcd_draw_string(8, 70, line2, TERM_GREEN_DIM, TERM_BG);
  lcd_flush();
  gpio_set_level((gpio_num_t)LCD_BL_PIN, 1);
  xSemaphoreGiveRecursive(display_mutex);
}

/**
 * Erase all settings and restart into setup mode
 */
static void factory_reset(void)
{
  ESP_LOGW(TAG_MAIN, "G0 held for %d s - erasing all settings", FACTORY_RESET_HOLD_MS / 1000);
  clear_wifi_config();
  draw_reset_screen("Settings erased", "Release G0 to restart");

  // G0 is a strapping pin: restarting while it is held would enter download mode
  while (gpio_get_level((gpio_num_t)BUTTON_G0_PIN) == 0)
    vTaskDelay(pdMS_TO_TICKS(50));
  esp_restart();
}

/**
 * UI task: G0 button, screen timeout and battery measurement.
 * A short press on G0 wakes the screen, holding it for 5 s erases all settings.
 */
/* ═══════════════════════════════════════════════════════════════════
 * POWER SETTINGS (web panel and E / P keys)
 * ═══════════════════════════════════════════════════════════════════ */

/* CPU clock: 80-160 MHz in eco mode, else fixed (no light sleep - the AP must stay up) */
static void apply_eco_mode(bool eco)
{
  esp_pm_config_t pm_config = {};
  pm_config.max_freq_mhz = eco ? 160 : CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
  pm_config.min_freq_mhz = eco ? 80 : CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
  pm_config.light_sleep_enable = false;
  esp_err_t err = esp_pm_configure(&pm_config);
  ESP_LOGI(TAG_MAIN, "CPU clock %d-%d MHz: %s", pm_config.min_freq_mhz, pm_config.max_freq_mhz, esp_err_to_name(err));
}

/* WiFi transmit power limit in dBm, 0 = maximum (the API uses 0.25 dBm units) */
static void apply_tx_power(uint8_t dbm)
{
  esp_err_t err = esp_wifi_set_max_tx_power(dbm == 0 ? 84 : (int8_t)(dbm * 4));
  ESP_LOGI(TAG_MAIN, "WiFi transmit power %s%u dBm: %s", dbm == 0 ? "max " : "", (unsigned)(dbm == 0 ? 20 : dbm),
           esp_err_to_name(err));
}

/* Remember a setting changed with a key (same NVS keys as the web panel) */
static void save_setting_u8(const char *key, uint8_t value)
{
  nvs_handle_t nvs;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK)
  {
    nvs_set_u8(nvs, key, value);
    nvs_commit(nvs);
    nvs_close(nvs);
  }
}

/* P key: next lower transmit power, from the lowest back to maximum */
static void cycle_tx_power(void)
{
  const size_t count = sizeof(TX_POWER_OPTIONS) / sizeof(TX_POWER_OPTIONS[0]);
  size_t next = 0;
  for (size_t i = 0; i < count; i++)
    if (TX_POWER_OPTIONS[i].dbm == stored_config.tx_power)
      next = (i + 1) % count;
  stored_config.tx_power = TX_POWER_OPTIONS[next].dbm;
  apply_tx_power(stored_config.tx_power);
  save_setting_u8(NVS_KEY_TX_POWER, stored_config.tx_power);
}

/* E key: eco mode on/off */
static void toggle_eco_mode(void)
{
  stored_config.eco_mode = !stored_config.eco_mode;
  apply_eco_mode(stored_config.eco_mode);
  save_setting_u8(NVS_KEY_ECO_MODE, stored_config.eco_mode ? 1 : 0);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEYBOARD (Cardputer ADV)
 * ═══════════════════════════════════════════════════════════════════ */

static i2c_master_dev_handle_t keyboard_dev = NULL;

static esp_err_t tca8418_write(uint8_t reg, uint8_t value)
{
  uint8_t buf[2] = {reg, value};
  return i2c_master_transmit(keyboard_dev, buf, sizeof(buf), 50);
}

static esp_err_t tca8418_read(uint8_t reg, uint8_t *value)
{
  return i2c_master_transmit_receive(keyboard_dev, &reg, 1, value, 1, 50);
}

/**
 * Set up the TCA8418 as a 7x8 key matrix (like the M5Cardputer library).
 * Key events are polled, the interrupt pin is not used.
 */
static bool keyboard_init(void)
{
  i2c_master_bus_config_t bus_config = {};
  bus_config.i2c_port = -1; // any free controller
  bus_config.sda_io_num = (gpio_num_t)KEYBOARD_SDA_PIN;
  bus_config.scl_io_num = (gpio_num_t)KEYBOARD_SCL_PIN;
  bus_config.clk_source = I2C_CLK_SRC_DEFAULT;
  bus_config.glitch_ignore_cnt = 7;
  bus_config.flags.enable_internal_pullup = true;

  i2c_master_bus_handle_t bus = NULL;
  if (i2c_new_master_bus(&bus_config, &bus) != ESP_OK)
    return false;
  if (i2c_master_probe(bus, TCA8418_ADDR, 50) != ESP_OK)
  {
    ESP_LOGW(TAG_MAIN, "Keyboard: no TCA8418 found (not a Cardputer ADV?) - V key disabled");
    i2c_del_master_bus(bus);
    return false;
  }

  i2c_device_config_t dev_config = {};
  dev_config.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dev_config.device_address = TCA8418_ADDR;
  dev_config.scl_speed_hz = 400000;
  if (i2c_master_bus_add_device(bus, &dev_config, &keyboard_dev) != ESP_OK)
    return false;

  tca8418_write(TCA8418_REG_KP_GPIO_1, 0x7F); // rows 0-6
  tca8418_write(TCA8418_REG_KP_GPIO_2, 0xFF); // columns 0-7
  tca8418_write(TCA8418_REG_KP_GPIO_3, 0x00);
  tca8418_write(TCA8418_REG_CFG, 0x01);       // key event interrupt (KE_IEN)

  // Drop events from before the start
  uint8_t event = 0;
  for (int i = 0; i < 10 && tca8418_read(TCA8418_REG_KEY_EVENT_A, &event) == ESP_OK && event != 0; i++)
  {
  }
  tca8418_write(TCA8418_REG_INT_STAT, 0x03);
  ESP_LOGI(TAG_MAIN, "✓ Keyboard ready (V: VPN, P: transmit power, E: eco mode)");
  return true;
}

/**
 * Next key press from the keyboard FIFO (key number), 0 when none
 */
static uint8_t keyboard_read_press(void)
{
  if (!keyboard_dev)
    return 0;
  uint8_t count = 0;
  if (tca8418_read(TCA8418_REG_KEY_LCK_EC, &count) != ESP_OK || (count & 0x0F) == 0)
    return 0;

  uint8_t pressed = 0;
  for (int i = 0; i < (count & 0x0F); i++)
  {
    uint8_t event = 0;
    if (tca8418_read(TCA8418_REG_KEY_EVENT_A, &event) != ESP_OK || event == 0)
      break;
    if ((event & TCA8418_KEY_PRESSED) && pressed == 0)
      pressed = event & 0x7F;
  }
  tca8418_write(TCA8418_REG_INT_STAT, 0x01);
  return pressed;
}

static bool wg_configured(void)
{
  return strlen(stored_config.wg_private_key) == WG_KEY_B64_LEN &&
         strlen(stored_config.wg_peer_public_key) == WG_KEY_B64_LEN &&
         strlen(stored_config.wg_endpoint) > 0 && strlen(stored_config.wg_address) > 0;
}

static void ui_task(void *pvParameters)
{
  gpio_config_t button_config = {};
  button_config.pin_bit_mask = 1ULL << BUTTON_G0_PIN;
  button_config.mode = GPIO_MODE_INPUT;
  button_config.pull_up_en = GPIO_PULLUP_ENABLE;
  gpio_config(&button_config);

  bool was_pressed = false;
  TickType_t pressed_since = 0;
  int countdown_shown = -1;
  TickType_t last_battery_tick = xTaskGetTickCount();
  last_activity_tick = xTaskGetTickCount();
  if (!config_mode)
    keyboard_init();

  while (1)
  {
    TickType_t now = xTaskGetTickCount();
    bool pressed = gpio_get_level((gpio_num_t)BUTTON_G0_PIN) == 0;

    if (pressed && !was_pressed)
    {
      pressed_since = now;
      display_wake();
    }
    else if (pressed)
    {
      uint32_t held_ms = (now - pressed_since) * portTICK_PERIOD_MS;
      if (held_ms >= FACTORY_RESET_HOLD_MS)
      {
        factory_reset();
      }
      else if (held_ms >= 1000)
      {
        int remaining = (FACTORY_RESET_HOLD_MS - held_ms + 999) / 1000;
        if (remaining != countdown_shown)
        {
          char line[32];
          snprintf(line, sizeof(line), "Erasing settings in %d s", remaining);
          draw_reset_screen(line, "Release G0 to cancel");
          countdown_shown = remaining;
        }
      }
    }
    else if (was_pressed)
    {
      // Released before the reset: leave the countdown, restart the screen timeout
      countdown_shown = -1;
      reset_screen_shown = false;
      display_wake();
    }
    was_pressed = pressed;

    // V: switch the VPN on/off (done in the status task, next to the tunnel updates)
    uint8_t key = keyboard_read_press();
    if (key == KEY_V && status_task_handle)
    {
      wg_toggle_requested = true;
      xTaskNotifyGive(status_task_handle);
      display_wake();
    }
    else if (key == KEY_P)
    {
      cycle_tx_power();
      display_wake();
    }
    else if (key == KEY_E)
    {
      toggle_eco_mode();
      display_wake();
    }
    else if (key != 0)
    {
      ESP_LOGD(TAG_MAIN, "Key %u pressed", key);
      display_wake();
    }

    // Screen timeout (the screen stays on in setup mode)
    if (!config_mode && stored_config.display_timeout > 0 && !pressed)
      display_sleep_if_idle((TickType_t)stored_config.display_timeout * configTICK_RATE_HZ);

    if (now - last_battery_tick >= pdMS_TO_TICKS(10000))
    {
      battery_sample();
      last_battery_tick = now;
    }

    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

/**
 * Set the DNS server offered to AP clients by the DHCP server
 */
static void set_ap_dhcp_dns(const esp_netif_dns_info_t *dns)
{
  // Stop DHCP server
  esp_netif_dhcps_stop(ap_netif);

  // Enable DNS option
  uint8_t dhcps_offer_option = DHCPS_OFFER_DNS;
  esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                         &dhcps_offer_option, sizeof(dhcps_offer_option));

  // Set DNS info
  esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, (esp_netif_dns_info_t *)dns);

  // Restart DHCP server
  esp_netif_dhcps_start(ap_netif);
}

/**
 * Offer this device as DNS server to AP clients (DNS proxy)
 */
static void offer_dns_proxy(void)
{
  esp_netif_ip_info_t ap_ip;
  esp_netif_get_ip_info(ap_netif, &ap_ip);
  esp_netif_dns_info_t dns = {};
  dns.ip.type = ESP_IPADDR_TYPE_V4;
  dns.ip.u_addr.ip4 = ap_ip.ip;
  set_ap_dhcp_dns(&dns);
}

/**
 * Forward DNS settings from STA interface to AP's DHCP server
 * (or offer the configured VPN DNS when WireGuard is enabled).
 * With portal redirect clients use the DNS proxy, which forwards instead.
 */
static void setup_dns_forwarding(void)
{
  if (!sta_netif || !ap_netif)
  {
    ESP_LOGE(TAG_MAIN, "Network interfaces not initialized");
    return;
  }

  if (stored_config.portal_redirect)
  {
    offer_dns_proxy(); // the AP address may have changed (subnet conflict)
    return;
  }

  esp_netif_dns_info_t dns = {};
  if (stored_config.wg_enabled && strlen(stored_config.wg_dns) > 0)
  {
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = ipaddr_addr(stored_config.wg_dns);
    ESP_LOGI(TAG_MAIN, "Offering VPN DNS: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));
    set_ap_dhcp_dns(&dns);
    return;
  }

  esp_err_t err = esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns);

  if (err == ESP_OK)
  {
    ESP_LOGI(TAG_MAIN, "Forwarding DNS: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));
    set_ap_dhcp_dns(&dns);
    ESP_LOGI(TAG_MAIN, "DNS forwarding configured successfully");
  }
  else
  {
    ESP_LOGE(TAG_MAIN, "Failed to get DNS info from STA interface");
  }
}

/**
 * HTTP client event handler for the connectivity probe - remembers the
 * redirect target, which is the captive portal login page
 */
static esp_err_t probe_http_event_handler(esp_http_client_event_t *evt)
{
  if (evt->event_id == HTTP_EVENT_ON_HEADER && strcasecmp(evt->header_key, "Location") == 0)
  {
    strlcpy((char *)evt->user_data, evt->header_value, sizeof(portal_url));
  }
  return ESP_OK;
}

typedef enum
{
  PROBE_ONLINE, // the expected answer of a free internet connection
  PROBE_PORTAL, // some other HTTP answer - a captive portal intercepts traffic
  PROBE_FAILED  // no HTTP answer at all
} probe_result_t;

/**
 * Run one connectivity probe over the uplink interface (independent of the
 * WireGuard tunnel). Stores a redirect target in location and a short
 * description of the result in info.
 */
static probe_result_t run_connectivity_probe(const connectivity_probe_t *probe, char *location,
                                             char *info, size_t info_len)
{
  struct ifreq ifr = {};
  esp_netif_get_netif_impl_name(sta_netif, ifr.ifr_name);

  location[0] = '\0';
  esp_http_client_config_t config = {};
  config.url = probe->url;
  config.timeout_ms = PROBE_TIMEOUT_MS;
  config.disable_auto_redirect = true;
  config.event_handler = probe_http_event_handler;
  config.user_data = location;
  config.if_name = &ifr;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client)
  {
    snprintf(info, info_len, "%s: out of memory", probe->url);
    return PROBE_FAILED;
  }

  probe_result_t result = PROBE_FAILED;
  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK)
  {
    snprintf(info, info_len, "%s: %s", probe->url, esp_err_to_name(err));
  }
  else if (esp_http_client_fetch_headers(client) < 0)
  {
    snprintf(info, info_len, "%s: no HTTP answer", probe->url);
  }
  else
  {
    int status = esp_http_client_get_status_code(client);
    char body[96];
    int len = esp_http_client_read(client, body, sizeof(body) - 1);
    body[len > 0 ? len : 0] = '\0';

    bool ok = status == probe->ok_status && (!probe->ok_body || strstr(body, probe->ok_body));
    result = ok ? PROBE_ONLINE : PROBE_PORTAL;
    snprintf(info, info_len, "%s: HTTP %d%s", probe->url, status, ok ? " (OK)" : "");
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return result;
}

/**
 * Captive portals that block all traffic often answer DNS queries for
 * every name with their own (private) address. Returns true and the
 * portal address as login URL when the probe host resolves like that.
 */
static bool detect_dns_hijack(char *location, size_t location_len, char *info, size_t info_len)
{
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo("connectivitycheck.gstatic.com", NULL, &hints, &res) != 0 || !res)
  {
    snprintf(info, info_len, "DNS: no answer from the uplink DNS server");
    return false;
  }
  ip4_addr_t addr;
  addr.addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  freeaddrinfo(res);

  uint32_t a = ntohl(addr.addr);
  bool hijacked = (a >> 24) == 10 ||                // 10.0.0.0/8
                  (a >> 20) == ((172 << 4) | 1) ||  // 172.16.0.0/12
                  (a >> 16) == ((192 << 8) | 168) || // 192.168.0.0/16
                  (a >> 22) == ((100 << 2) | 1) ||  // 100.64.0.0/10 (CGNAT)
                  a == 0x01010101;                  // 1.1.1.1 - common virtual portal address

  char ip[16];
  ip4addr_ntoa_r(&addr, ip, sizeof(ip));
  snprintf(info, info_len, "DNS: connectivitycheck.gstatic.com -> %s%s", ip,
           hijacked ? " (redirected by the network)" : "");
  if (hijacked)
    snprintf(location, location_len, "http://%s/", ip);
  return hijacked;
}

/**
 * Check internet connectivity and detect captive portals.
 *
 * Requests URLs that give a known answer on a free internet connection.
 * Any other HTTP answer means a captive portal intercepts traffic. When
 * no probe gets an answer, a DNS answer pointing to a private address
 * still reveals a portal. The requests are bound to the uplink interface
 * so the result is independent of the WireGuard tunnel.
 */
static void check_internet_connectivity(void)
{
  if (!sta_connected)
  {
    uplink_state = UPLINK_OFFLINE;
    return;
  }

  ESP_LOGI(TAG_MAIN, "Checking internet connectivity...");

  char location[sizeof(portal_url)];
  char info[sizeof(probe_info)];
  char portal_location[sizeof(portal_url)] = {0};
  char portal_info[sizeof(probe_info)] = {0};
  char failed_info[sizeof(probe_info)] = {0};
  bool portal_seen = false;

  for (size_t i = 0; i < sizeof(CONNECTIVITY_PROBES) / sizeof(CONNECTIVITY_PROBES[0]); i++)
  {
    probe_result_t result = run_connectivity_probe(&CONNECTIVITY_PROBES[i], location, info, sizeof(info));
    ESP_LOGI(TAG_MAIN, "  %s", info);

    if (result == PROBE_ONLINE)
    {
      ESP_LOGI(TAG_MAIN, "✓ Internet connectivity confirmed");
      strlcpy(probe_info, info, sizeof(probe_info));
      portal_url[0] = '\0';
      uplink_state = UPLINK_ONLINE;
      return;
    }
    if (result == PROBE_PORTAL && !portal_seen)
    {
      // Keep checking - a single blocked probe host is no portal
      portal_seen = true;
      strlcpy(portal_location, location, sizeof(portal_location));
      strlcpy(portal_info, info, sizeof(portal_info));
    }
    else if (result == PROBE_FAILED && failed_info[0] == '\0')
    {
      strlcpy(failed_info, info, sizeof(failed_info));
    }
  }

  if (!portal_seen)
  {
    portal_seen = detect_dns_hijack(portal_location, sizeof(portal_location), portal_info, sizeof(portal_info));
    if (!portal_seen)
    {
      strlcpy(probe_info, failed_info, sizeof(probe_info));
      strlcat(probe_info, "; ", sizeof(probe_info));
      strlcat(probe_info, portal_info, sizeof(probe_info));
      ESP_LOGW(TAG_MAIN, "✗ No internet connectivity (%s)", probe_info);
      uplink_state = UPLINK_NO_INTERNET;
      return;
    }
  }

  strlcpy(portal_url, portal_location, sizeof(portal_url));
  strlcpy(probe_info, portal_info, sizeof(probe_info));
  ESP_LOGW(TAG_MAIN, "⚠ Captive portal detected (%s) - login at: %s",
           probe_info, strlen(portal_url) > 0 ? portal_url : PORTAL_FALLBACK_URL);
  uplink_state = UPLINK_PORTAL;
}

/* ═══════════════════════════════════════════════════════════════════
 * WIREGUARD VPN
 * ═══════════════════════════════════════════════════════════════════ */

/* lwIP is not thread safe - these run inside the TCP/IP task */
static esp_err_t wg_init_cb(void *ctx) { return esp_wireguard_init(&wg_config, (wireguard_ctx_t *)ctx); }
static esp_err_t wg_connect_cb(void *ctx) { return esp_wireguard_connect((wireguard_ctx_t *)ctx); }
static esp_err_t wg_disconnect_cb(void *ctx) { return esp_wireguard_disconnect((wireguard_ctx_t *)ctx); }
static esp_err_t wg_peer_is_up_cb(void *ctx) { return esp_wireguard_peer_is_up((wireguard_ctx_t *)ctx); }

static esp_err_t wg_snapshot_cb(void *arg)
{
  wg_peer_snapshot_t *snap = (wg_peer_snapshot_t *)arg;
  if (!wg_ctx.netif || !wg_ctx.netif->state)
    return ESP_ERR_INVALID_STATE;
  const struct wireguard_peer *peer = &((struct wireguard_device *)wg_ctx.netif->state)->peers[0];
  if (!peer->valid)
    return ESP_ERR_INVALID_STATE;
  snap->valid = true;
  snap->endpoint_ip = peer->connect_ip;
  snap->endpoint_port = peer->connect_port;
  snap->seen_ip = peer->ip;
  snap->seen_port = peer->port;
  snap->now = wireguard_sys_now();
  snap->latest_handshake = peer->latest_handshake_millis;
  snap->last_initiation_tx = peer->last_initiation_tx;
  snap->last_rx = peer->last_rx;
  snap->last_tx = peer->last_tx;
  return ESP_OK;
}
static esp_err_t wg_set_default_cb(void *ctx) { return esp_wireguard_set_default((wireguard_ctx_t *)ctx); }
static esp_err_t wg_restore_default_cb(void *ctx) { return esp_wireguard_restore_default((wireguard_ctx_t *)ctx); }
static esp_err_t wg_allow_all_cb(void *ctx)
{
  // Full tunnel: accept and route any address through the peer
  return esp_wireguard_add_allowed_ip((wireguard_ctx_t *)ctx, "0.0.0.0", "0.0.0.0");
}

/*
 * TCP MSS clamping. The tunnel MTU is 1420, while clients assume 1500: full
 * size TCP segments would not fit and stall or get fragmented. Lowering the
 * MSS option of SYN segments in both directions makes both ends send
 * segments that fit the tunnel.
 */
static netif_output_fn wg_output_orig = NULL;
static netif_output_fn ap_output_orig = NULL;
static uint16_t tunnel_mss = 0;

/**
 * Incremental Internet checksum update for one changed 16-bit word (RFC 1624)
 */
static uint16_t checksum_replace_word(uint16_t checksum, uint16_t old_word, uint16_t new_word)
{
  uint32_t sum = (uint16_t)~checksum + (uint16_t)~old_word + new_word;
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

/**
 * Lower the MSS option of an IPv4 TCP SYN segment to max_mss, in place
 */
static void clamp_tcp_mss(uint8_t *packet, size_t len, uint16_t max_mss)
{
  if (len < 20 || (packet[0] >> 4) != 4 || packet[9] != IP_PROTO_TCP)
    return;
  // Only unfragmented packets (MF flag and fragment offset zero)
  if ((packet[6] & 0x3F) != 0 || packet[7] != 0)
    return;
  size_t ip_hlen = (packet[0] & 0x0F) * 4;
  if (ip_hlen < 20 || len < ip_hlen + 20)
    return;

  uint8_t *tcp = packet + ip_hlen;
  size_t tcp_hlen = (tcp[12] >> 4) * 4;
  if (!(tcp[13] & 0x02) || tcp_hlen < 20 || len < ip_hlen + tcp_hlen)
    return; // not a SYN or truncated

  for (size_t i = 20; i < tcp_hlen;)
  {
    uint8_t kind = tcp[i];
    if (kind == 0) // end of option list
      break;
    if (kind == 1) // NOP
    {
      i++;
      continue;
    }
    if (i + 1 >= tcp_hlen || tcp[i + 1] < 2 || i + tcp[i + 1] > tcp_hlen)
      break; // malformed
    if (kind == 2 && tcp[i + 1] == 4) // MSS
    {
      uint16_t mss = (tcp[i + 2] << 8) | tcp[i + 3];
      if (mss <= max_mss)
        return;

      // The value may start at an odd offset and then spans two checksum words
      size_t first = (i + 2) & ~(size_t)1;
      size_t words = ((i + 2) & 1) ? 2 : 1;
      uint16_t old_words[2];
      for (size_t w = 0; w < words; w++)
        old_words[w] = (tcp[first + 2 * w] << 8) | tcp[first + 2 * w + 1];

      tcp[i + 2] = max_mss >> 8;
      tcp[i + 3] = max_mss & 0xFF;

      uint16_t checksum = (tcp[16] << 8) | tcp[17];
      for (size_t w = 0; w < words; w++)
        checksum = checksum_replace_word(checksum, old_words[w], (tcp[first + 2 * w] << 8) | tcp[first + 2 * w + 1]);
      tcp[16] = checksum >> 8;
      tcp[17] = checksum & 0xFF;
      return;
    }
    i += tcp[i + 1];
  }
}

/* Clients -> tunnel: SYN of new connections */
static err_t wg_output_clamped(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr)
{
  clamp_tcp_mss((uint8_t *)p->payload, p->len, tunnel_mss);
  return wg_output_orig(netif, p, addr);
}

/* Tunnel -> clients: SYN-ACK of the servers (the AP interface sees all client traffic) */
static err_t ap_output_clamped(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr)
{
  if (wg_is_default)
    clamp_tcp_mss((uint8_t *)p->payload, p->len, tunnel_mss);
  return ap_output_orig(netif, p, addr);
}

/*
 * Kill switch: frames from AP clients enter here (WiFi task). While it is
 * active only ARP, broadcast/multicast (DHCP) and packets to this device
 * (web panel, DNS proxy) get through - nothing is forwarded to the uplink.
 */
static netif_input_fn ap_input_orig = NULL;
static volatile uint32_t ap_ip_addr = 0; // network byte order, updated when the AP address changes

static err_t ap_input_filtered(struct pbuf *p, struct netif *netif)
{
  if (kill_switch_active() && p->len >= 34)
  {
    const uint8_t *frame = (const uint8_t *)p->payload;
    uint16_t ethertype = (frame[12] << 8) | frame[13];
    if (ethertype == 0x0800)
    {
      uint32_t dst;
      memcpy(&dst, frame + 14 + 16, 4);
      uint8_t first = frame[30]; // first byte of the destination address
      bool local = dst == ap_ip_addr || dst == 0xFFFFFFFF || (first >= 224 && first <= 239) ||
                   (frame[0] & 0x01); // broadcast/multicast frame (DHCP, mDNS)
      if (!local)
      {
        kill_switch_drops = kill_switch_drops + 1;
        pbuf_free(p);
        return ERR_OK;
      }
    }
  }
  return ap_input_orig(p, netif);
}

static esp_err_t ap_install_input_filter_cb(void *ctx)
{
  struct netif *ap_lwip_netif = (struct netif *)esp_netif_get_netif_impl(ap_netif);
  if (!ap_lwip_netif)
    return ESP_FAIL;
  ap_ip_addr = ip4_addr_get_u32(netif_ip4_addr(ap_lwip_netif));
  if (ap_lwip_netif->input != ap_input_filtered)
  {
    ap_input_orig = ap_lwip_netif->input;
    ap_lwip_netif->input = ap_input_filtered;
  }
  return ESP_OK;
}

/* Wrap the output functions of the tunnel and AP interfaces (TCP/IP task) */
static esp_err_t wg_install_mss_clamping_cb(void *ctx)
{
  struct netif *wg_netif = wg_ctx.netif;
  struct netif *ap_lwip_netif = (struct netif *)esp_netif_get_netif_impl(ap_netif);
  if (!wg_netif || !ap_lwip_netif)
    return ESP_FAIL;

  tunnel_mss = wg_netif->mtu - 40; // IPv4 and TCP headers without options
  if (wg_netif->output != wg_output_clamped)
  {
    wg_output_orig = wg_netif->output;
    wg_netif->output = wg_output_clamped;
  }
  if (ap_lwip_netif->output != ap_output_clamped)
  {
    ap_output_orig = ap_lwip_netif->output;
    ap_lwip_netif->output = ap_output_clamped;
  }
  return ESP_OK;
}

/**
 * Synchronize the clock via SNTP. WireGuard handshakes carry a timestamp
 * and peers reject handshakes older than the last one they have seen, so
 * a clock starting at 1970 after every reboot would not work.
 */
static bool wg_sync_time(void)
{
  static bool sntp_started = false;
  if (!sntp_started)
  {
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&config);
    sntp_started = true;
  }

  time_t now = time(NULL);
  if (now < 1700000000)
  {
    esp_netif_sntp_sync_wait(pdMS_TO_TICKS(10000));
    now = time(NULL);
  }
  if (now < 1700000000)
  {
    ESP_LOGW(TAG_MAIN, "WireGuard: waiting for time sync");
    return false;
  }
  return true;
}

/**
 * Start the tunnel and route client traffic through it.
 *
 * The tunnel becomes the default route only while the uplink has real
 * internet access - during captive portal login clients must reach the
 * portal directly. Called periodically from the status task.
 */
static void wireguard_update(void)
{
  if (!stored_config.wg_enabled || !sta_connected)
    return;

  if (!wg_connected)
  {
    // Wait until a captive portal (if any) has been passed
    if (uplink_state != UPLINK_ONLINE)
    {
      strlcpy(wg_status, "waiting for internet access on the uplink", sizeof(wg_status));
      return;
    }
    if (!wg_sync_time())
    {
      strlcpy(wg_status, "waiting for time sync (SNTP, pool.ntp.org)", sizeof(wg_status));
      return;
    }

    if (!wg_initialized)
    {
      if (!parse_cidr(stored_config.wg_address, wg_ip, sizeof(wg_ip), wg_netmask, sizeof(wg_netmask)))
      {
        ESP_LOGE(TAG_MAIN, "WireGuard: invalid address %s", stored_config.wg_address);
        strlcpy(wg_status, "invalid interface address", sizeof(wg_status));
        return;
      }
      memset(&wg_config, 0, sizeof(wg_config));
      wg_config.private_key = stored_config.wg_private_key;
      wg_config.public_key = stored_config.wg_peer_public_key;
      wg_config.preshared_key = strlen(stored_config.wg_preshared_key) > 0 ? stored_config.wg_preshared_key : NULL;
      wg_config.address = wg_ip;
      wg_config.netmask = wg_netmask;
      wg_config.endpoint = stored_config.wg_endpoint;
      wg_config.port = stored_config.wg_port;
      wg_config.persistent_keepalive = stored_config.wg_keepalive;

      esp_err_t err = esp_netif_tcpip_exec(wg_init_cb, &wg_ctx);
      if (err != ESP_OK)
      {
        ESP_LOGE(TAG_MAIN, "WireGuard: init failed: %s", esp_err_to_name(err));
        snprintf(wg_status, sizeof(wg_status), "init failed: %s", esp_err_to_name(err));
        return;
      }
      wg_initialized = true;
    }

    // Endpoint hostname is resolved asynchronously - retry a few times
    esp_err_t err = ESP_FAIL;
    for (int attempt = 0; attempt < 5; attempt++)
    {
      err = esp_netif_tcpip_exec(wg_connect_cb, &wg_ctx);
      if (err != ESP_ERR_RETRY)
        break;
      vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (err == ESP_OK)
    {
      err = esp_netif_tcpip_exec(wg_allow_all_cb, &wg_ctx);
      if (err != ESP_OK)
      {
        ESP_LOGE(TAG_MAIN, "WireGuard: failed to allow 0.0.0.0/0: %s", esp_err_to_name(err));
      }
      if (esp_netif_tcpip_exec(wg_install_mss_clamping_cb, NULL) == ESP_OK)
      {
        ESP_LOGI(TAG_MAIN, "WireGuard: TCP MSS clamped to %u for the tunnel", tunnel_mss);
      }
      wg_connected = true;
      wg_connect_us = esp_timer_get_time();
      strlcpy(wg_status, "handshake pending", sizeof(wg_status));
      ESP_LOGI(TAG_MAIN, "WireGuard: connecting to %s:%d", stored_config.wg_endpoint, stored_config.wg_port);
    }
    else if (err == ESP_ERR_RETRY)
    {
      strlcpy(wg_status, "resolving the endpoint host name", sizeof(wg_status));
    }
    else
    {
      ESP_LOGE(TAG_MAIN, "WireGuard: connect failed: %s", esp_err_to_name(err));
      snprintf(wg_status, sizeof(wg_status), "connect failed: %s (endpoint host name?)", esp_err_to_name(err));
      // Reset the interface so the next attempt starts clean
      if (wg_ctx.netif)
        esp_netif_tcpip_exec(wg_disconnect_cb, &wg_ctx);
    }
    return;
  }

  wg_peer_up = esp_netif_tcpip_exec(wg_peer_is_up_cb, &wg_ctx) == ESP_OK;
  if (!wg_peer_up)
    strlcpy(wg_status, "handshake pending", sizeof(wg_status));

  // esp_netif may switch the default route back to STA (e.g. after a reconnect),
  // so compare with the actual lwIP default instead of a remembered flag
  wg_is_default = wg_ctx.netif != NULL && netif_default == wg_ctx.netif;

  bool want_default = wg_peer_up && uplink_state == UPLINK_ONLINE;
  if (want_default && !wg_is_default)
  {
    if (esp_netif_tcpip_exec(wg_set_default_cb, &wg_ctx) == ESP_OK)
    {
      wg_is_default = true;
      ESP_LOGI(TAG_MAIN, "✓ WireGuard tunnel up - routing client traffic through VPN");
    }
  }
  else if (!want_default && wg_is_default)
  {
    esp_netif_tcpip_exec(wg_restore_default_cb, &wg_ctx);
    wg_is_default = false;
    ESP_LOGW(TAG_MAIN, "WireGuard: %s - routing directly via uplink",
             wg_peer_up ? "uplink needs login" : "peer down");
  }

  if (wg_peer_up)
    strlcpy(wg_status, wg_is_default ? "tunnel up, routing client traffic" : "peer up, waiting for internet on the uplink",
            sizeof(wg_status));
}

/**
 * Enable NAPT (NAT) on the AP interface
 */
static void enable_napt(void)
{
  if (!ap_netif)
  {
    ESP_LOGE(TAG_MAIN, "AP interface not initialized");
    return;
  }

  ESP_LOGI(TAG_MAIN, "Enabling NAPT on AP interface...");

  // Enable NAPT on the AP interface
  esp_err_t err = esp_netif_napt_enable(ap_netif);

  if (err == ESP_OK)
  {
    ESP_LOGI(TAG_MAIN, "✓ NAPT enabled successfully!");
    napt_enabled = true;
  }
  else
  {
    ESP_LOGE(TAG_MAIN, "✗ Failed to enable NAPT: %s", esp_err_to_name(err));
  }
}

/* AP subnets (/24) to use when the uplink network overlaps the current one */
static const char *const AP_SUBNET_CANDIDATES[] = {"192.168.4.1", "192.168.44.1", "10.44.0.1", "172.31.44.1"};

/**
 * True when two IPv4 networks overlap (addresses and masks in network byte order)
 */
static bool subnets_overlap(uint32_t a, uint32_t a_mask, uint32_t b, uint32_t b_mask)
{
  uint32_t mask = a_mask & b_mask; // mask of the larger network
  return (a & mask) == (b & mask);
}

/**
 * Move the AP to a free subnet if the uplink network overlaps it - with both
 * interfaces in one subnet clients could not reach the internet
 */
static void ensure_ap_subnet_free(const esp_netif_ip_info_t *uplink)
{
  esp_netif_ip_info_t ap_info;
  esp_netif_get_ip_info(ap_netif, &ap_info);
  if (!subnets_overlap(ap_info.ip.addr, ap_info.netmask.addr, uplink->ip.addr, uplink->netmask.addr))
    return;

  for (size_t i = 0; i < sizeof(AP_SUBNET_CANDIDATES) / sizeof(AP_SUBNET_CANDIDATES[0]); i++)
  {
    esp_netif_ip_info_t candidate = {};
    candidate.ip.addr = ipaddr_addr(AP_SUBNET_CANDIDATES[i]);
    candidate.gw.addr = candidate.ip.addr;
    candidate.netmask.addr = ipaddr_addr("255.255.255.0");
    if (subnets_overlap(candidate.ip.addr, candidate.netmask.addr, uplink->ip.addr, uplink->netmask.addr))
      continue;

    ESP_LOGW(TAG_AP, "Uplink address " IPSTR " is in the AP subnet - moving the AP to %s",
             IP2STR(&uplink->ip), AP_SUBNET_CANDIDATES[i]);
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &candidate);
    esp_netif_dhcps_start(ap_netif);
    strlcpy(ap_ip_str, AP_SUBNET_CANDIDATES[i], sizeof(ap_ip_str));
    ap_ip_addr = candidate.ip.addr; // kill switch filter
    esp_wifi_deauth_sta(0); // clients reconnect and get an address in the new subnet
    return;
  }
  ESP_LOGE(TAG_AP, "No free AP subnet for uplink address " IPSTR, IP2STR(&uplink->ip));
}

/**
 * WiFi event handler
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
  /* AP Events */
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
  {
    wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
    ap_client_count++;
    ESP_LOGI(TAG_AP, "Station %02x:%02x:%02x:%02x:%02x:%02x joined, AID=%d",
             event->mac[0], event->mac[1], event->mac[2],
             event->mac[3], event->mac[4], event->mac[5],
             event->aid);
    display_wake();
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
  {
    wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
    if (ap_client_count > 0)
      ap_client_count--;
    ESP_LOGI(TAG_AP, "Station %02x:%02x:%02x:%02x:%02x:%02x left, AID=%d",
             event->mac[0], event->mac[1], event->mac[2],
             event->mac[3], event->mac[4], event->mac[5],
             event->aid);
    display_wake();
  }

  /* Station Events */
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
  {
    // In setup mode the station only exists for WiFi scanning
    if (!config_mode)
    {
      ESP_LOGI(TAG_STA, "Station started, connecting to AP...");
      start_uplink_connect();
    }
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE)
  {
    // Only the scan that picks the uplink network - the web panel scans on its own
    if (uplink_scan_pending)
    {
      uplink_scan_pending = false;
      uplink_scan_done();
    }
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
  {
    wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)event_data;
    bool was_connected = sta_connected;
    sta_connected = false;
    uplink_state = UPLINK_OFFLINE;
    last_disconnect_reason = event->reason;
    last_disconnect_us = esp_timer_get_time();
    disconnect_count++;
    ESP_LOGW(TAG_STA, "Uplink disconnected (reason %d: %s)", event->reason, disconnect_reason_text(event->reason));

    // No network with the expected security: with a saved password try the
    // network as an open one, and back (the network may change security)
    if ((event->reason == WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD ||
         event->reason == WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY) &&
        strlen(network_password(active_network)) > 0 && !scan_in_progress)
    {
      sta_open_fallback = !sta_open_fallback;
      ESP_LOGW(TAG_STA, "%s", sta_open_fallback ? "Uplink may be an open network - connecting without password"
                                                : "Connecting with the saved password again");
      apply_sta_config(sta_open_fallback);
      reconnect_delay_ms = WIFI_RECONNECT_MIN_MS;
    }

    // The WiFi scan pauses reconnecting and restarts it when done
    if (!scan_in_progress)
      schedule_reconnect();

    if (was_connected)
      display_wake(); // show that the uplink was lost
    else
      display_update_status();
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
  {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG_STA, "✓ Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    reconnect_delay_ms = WIFI_RECONNECT_MIN_MS;
    connected_since_us = esp_timer_get_time();
    sta_connected = true;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

    /* Keep the AP out of the uplink's subnet, then configure DNS and NAPT */
    ensure_ap_subnet_free(&event->ip_info);
    setup_dns_forwarding();
    if (!napt_enabled)
    {
      enable_napt();
    }

    /* Check internet connectivity / captive portal in the status task */
    uplink_state = UPLINK_CHECKING;
    if (status_task_handle)
    {
      xTaskNotifyGive(status_task_handle);
    }

    display_wake();
  }
}

/**
 * Initialize WiFi Access Point
 */
static void wifi_init_softap(void)
{
  ap_netif = esp_netif_create_default_wifi_ap();

  wifi_config_t wifi_ap_config = {};

  /* Configure AP settings */
  memcpy(wifi_ap_config.ap.ssid, stored_config.ap_ssid, strlen(stored_config.ap_ssid));
  wifi_ap_config.ap.ssid_len = strlen(stored_config.ap_ssid);
  memcpy(wifi_ap_config.ap.password, stored_config.ap_password, strlen(stored_config.ap_password));
  wifi_ap_config.ap.channel = WIFI_AP_CHANNEL;
  wifi_ap_config.ap.max_connection = WIFI_AP_MAX_CONNECTIONS;

  /* Set auth mode based on password */
  if (strlen(stored_config.ap_password) > 0)
  {
    wifi_ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
  }
  else
  {
    wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;
  }

  wifi_ap_config.ap.pmf_cfg.required = false;

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));

  ESP_LOGI(TAG_AP, "✓ AP configured: SSID=%s, Channel=%d, Auth=%s",
           stored_config.ap_ssid, WIFI_AP_CHANNEL,
           strlen(stored_config.ap_password) > 0 ? "WPA2" : "OPEN");
}

/**
 * Initialize WiFi Station
 */
static void wifi_init_sta(void)
{
  sta_netif = esp_netif_create_default_wifi_sta();
  ESP_ERROR_CHECK(apply_sta_config(false));
  ESP_LOGI(TAG_STA, "✓ Station configured: connecting to SSID=%s", stored_config.sta_ssid);
}

/**
 * Stop the tunnel: clients go directly through the uplink again
 */
static void wireguard_stop(void)
{
  if (wg_connected && wg_ctx.netif)
    esp_netif_tcpip_exec(wg_disconnect_cb, &wg_ctx); // also restores the default route
  wg_connected = false;
  wg_peer_up = false;
  wg_is_default = false;
}

/**
 * V key: switch the VPN on or off and remember it (same setting as the
 * checkbox in the web panel)
 */
static void wireguard_toggle(void)
{
  bool enable = !stored_config.wg_enabled;
  if (enable && !wg_configured())
  {
    ESP_LOGW(TAG_MAIN, "VPN: not configured - set up WireGuard in the web panel first");
    strlcpy(wg_status, "not configured", sizeof(wg_status));
    return;
  }

  stored_config.wg_enabled = enable;
  if (!enable)
  {
    wireguard_stop();
    strlcpy(wg_status, "switched off (V key)", sizeof(wg_status));
  }
  ESP_LOGI(TAG_MAIN, "VPN %s (V key)", enable ? "ON" : "OFF");

  save_setting_u8(NVS_KEY_WG_ENABLED, enable ? 1 : 0);

  if (sta_connected)
    setup_dns_forwarding(); // VPN DNS for clients when portal redirect is off
}

/**
 * Status monitoring task - connectivity / captive portal checks and WireGuard
 */
static void status_task(void *pvParameters)
{
  while (1)
  {
    uplink_state_t previous_state = uplink_state;

    if (wg_toggle_requested)
    {
      wg_toggle_requested = false;
      wireguard_toggle();
    }

    if (sta_connected)
    {
      // Check internet connectivity - less often while online (battery)
      static TickType_t last_check = 0;
      TickType_t now = xTaskGetTickCount();
      if (uplink_state != UPLINK_ONLINE || last_check == 0 ||
          now - last_check >= pdMS_TO_TICKS(CHECK_INTERVAL_ONLINE_MS))
      {
        check_internet_connectivity();
        last_check = xTaskGetTickCount();
      }
      wireguard_update();

      wifi_ap_record_t ap_info;
      if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
      {
        ESP_LOGI(TAG_MAIN, "━━━ STATUS ━━━");
        ESP_LOGI(TAG_MAIN, "Uplink: %s | RSSI: %d dBm",
                 network_ssid(active_network), ap_info.rssi);
        ESP_LOGI(TAG_MAIN, "AP Clients: %d", ap_client_count);
        ESP_LOGI(TAG_MAIN, "NAT: %s", napt_enabled ? "✓ ACTIVE" : "✗ DISABLED");
        ESP_LOGI(TAG_MAIN, "Internet: %s",
                 uplink_state == UPLINK_ONLINE ? "✓ ONLINE" : (uplink_state == UPLINK_PORTAL ? "⚠ CAPTIVE PORTAL" : "✗ NO INTERNET"));
        if (stored_config.wg_enabled)
        {
          ESP_LOGI(TAG_MAIN, "WireGuard: %s",
                   wg_is_default ? "✓ ROUTING" : (wg_peer_up ? "⧗ PEER UP" : "⧗ CONNECTING"));
        }
        ESP_LOGI(TAG_MAIN, "Repeater: %s",
                 (sta_connected && uplink_state == UPLINK_ONLINE) ? "✓ READY" : "⧗ INITIALIZING");
      }
    }
    else
    {
      uplink_state = UPLINK_OFFLINE;
      ESP_LOGI(TAG_MAIN, "Waiting for uplink connection...");
    }

    // Update display - and turn it on when internet access is lost or a portal needs login
    if (sta_connected && uplink_state != previous_state && uplink_state != UPLINK_ONLINE)
      display_wake();
    else
      display_update_status();

    // Update every 10 seconds, or right away when the uplink gets an IP
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10000));
  }
}

/**
 * Main application entry point
 */
extern "C" void app_main(void)
{
  /* Keep recent log output for the web panel's debug page */
  serial_vprintf = esp_log_set_vprintf(debug_log_vprintf);

  ESP_LOGI(TAG_MAIN, "╔══════════════════════════════════════╗");
  ESP_LOGI(TAG_MAIN, "║   ESP32-S3 WiFi Repeater with NAT    ║");
  ESP_LOGI(TAG_MAIN, "╚══════════════════════════════════════╝");

  /* Initialize Display */
  ESP_LOGI(TAG_MAIN, "Initializing display...");
  display_init();
  ESP_LOGI(TAG_MAIN, "✓ Display initialized");

  /* Initialize NVS - Required for WiFi and config storage */
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  /* Load configuration */
  stored_config.wg_port = WG_DEFAULT_PORT;
  stored_config.wg_keepalive = WG_DEFAULT_KEEPALIVE;
  stored_config.display_timeout = DEFAULT_DISPLAY_TIMEOUT;
  stored_config.portal_redirect = true;
  ret = load_wifi_config(&stored_config);
  if (ret != ESP_OK)
  {
    ESP_LOGI(TAG_MAIN, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG_MAIN, "║  No Configuration Found                ║");
    ESP_LOGI(TAG_MAIN, "║  Entering Setup Mode                   ║");
    ESP_LOGI(TAG_MAIN, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG_MAIN, "");
    ESP_LOGI(TAG_MAIN, "Connect to WiFi: %s", DEFAULT_CONFIG_AP_SSID);
    ESP_LOGI(TAG_MAIN, "Then visit: http://%s", WEB_CONFIG_IP);
    ESP_LOGI(TAG_MAIN, "");

    // Set temporary AP-only configuration
    strncpy(stored_config.ap_ssid, DEFAULT_CONFIG_AP_SSID, sizeof(stored_config.ap_ssid));
    strncpy(stored_config.ap_password, DEFAULT_CONFIG_AP_PASSWORD, sizeof(stored_config.ap_password));
    stored_config.wg_port = WG_DEFAULT_PORT;
    stored_config.wg_keepalive = WG_DEFAULT_KEEPALIVE;
    stored_config.display_timeout = DEFAULT_DISPLAY_TIMEOUT;
  stored_config.portal_redirect = true;
    stored_config.configured = false;
    config_mode = true;
  }
  else
  {
    ESP_LOGI(TAG_MAIN, "✓ Configuration loaded:");
    ESP_LOGI(TAG_MAIN, "  Uplink SSID: %s", stored_config.sta_ssid);
    ESP_LOGI(TAG_MAIN, "  AP SSID: %s", stored_config.ap_ssid);
    ESP_LOGI(TAG_MAIN, "  AP Security: %s",
             strlen(stored_config.ap_password) > 0 ? "WPA2" : "Open");
    ESP_LOGI(TAG_MAIN, "  WireGuard: %s",
             stored_config.wg_enabled ? stored_config.wg_endpoint : "disabled");
    config_mode = false;
  }

  /* CPU clock: eco mode scales between 80 and 160 MHz */
  apply_eco_mode(stored_config.eco_mode && !config_mode);

  /* Battery gauge, G0 button and screen timeout */
  battery_init();
  battery_sample();
  xTaskCreate(ui_task, "ui_task", 4096, NULL, 4, NULL);
  display_update_status();

  /* Initialize TCP/IP stack */
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  /* Create event group */
  s_wifi_event_group = xEventGroupCreate();

  /* Register event handlers */
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                      ESP_EVENT_ANY_ID,
                                                      &wifi_event_handler,
                                                      NULL,
                                                      NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                      IP_EVENT_STA_GOT_IP,
                                                      &wifi_event_handler,
                                                      NULL,
                                                      NULL));

  /* Initialize WiFi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  if (config_mode)
  {
    /* Config mode: AP for configuration, idle STA for WiFi scanning */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    wifi_init_softap();
    sta_netif = esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG_MAIN, "✓ WiFi started in AP mode (config mode)");

    /* Captive portal: clients get our IP as DNS, every name resolves to us */
    esp_netif_ip_info_t ap_ip;
    esp_netif_get_ip_info(ap_netif, &ap_ip);
    esp_netif_dns_info_t ap_dns = {};
    ap_dns.ip.type = ESP_IPADDR_TYPE_V4;
    ap_dns.ip.u_addr.ip4 = ap_ip.ip;
    set_ap_dhcp_dns(&ap_dns);
    xTaskCreate(captive_dns_task, "captive_dns", 4096, NULL, 5, NULL);

    /* Start web server for configuration */
    vTaskDelay(pdMS_TO_TICKS(1000));
    start_webserver();

    ESP_LOGI(TAG_MAIN, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG_MAIN, "║  🔧 Configuration Mode Active         ║");
    ESP_LOGI(TAG_MAIN, "║                                       ║");
    ESP_LOGI(TAG_MAIN, "║  1. Connect to: %-21s║", stored_config.ap_ssid);
    ESP_LOGI(TAG_MAIN, "║  2. Visit: http://%-19s║", WEB_CONFIG_IP);
    ESP_LOGI(TAG_MAIN, "║  3. Configure WiFi settings           ║");
    ESP_LOGI(TAG_MAIN, "╚═══════════════════════════════════════╝");

    // Stay in config mode indefinitely
    while (1)
    {
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
  }
  else
  {
    /* Normal mode: AP+STA for repeater operation */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    /* Disable power saving for better performance */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG_MAIN, "✓ Power saving disabled for optimal performance");

    /* Initialize AP and STA */
    wifi_init_softap();
    wifi_init_sta();

    /* Uplink reconnect timer */
    esp_timer_create_args_t reconnect_timer_args = {};
    reconnect_timer_args.callback = reconnect_timer_cb;
    reconnect_timer_args.name = "wifi_reconnect";
    ESP_ERROR_CHECK(esp_timer_create(&reconnect_timer_args, &reconnect_timer));

    /* Create status monitoring task before WiFi starts so it gets notified on connect */
    xTaskCreate(status_task, "status_task", 8192, NULL, 5, &status_task_handle);

    /* Start WiFi */
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG_MAIN, "✓ WiFi started in AP+STA mode");

    /* Battery: transmit power limit */
    if (stored_config.tx_power > 0)
      apply_tx_power(stored_config.tx_power);

    /* Kill switch filter on the AP interface (inactive unless enabled) */
    esp_netif_tcpip_exec(ap_install_input_filter_cb, NULL);

    /* DNS proxy - lets clients open the uplink's captive portal login page */
    if (stored_config.portal_redirect)
    {
      offer_dns_proxy();
      xTaskCreate(dns_proxy_task, "dns_proxy", 4096, NULL, 5, NULL);
    }

    /* Start web server right away - also reachable when the uplink fails,
     * so the uplink can be fixed via WiFi scan */
    vTaskDelay(pdMS_TO_TICKS(1000));
    start_webserver();
    display_update_status();

    /* Wait for the first connection - reconnects keep running in the background */
    ESP_LOGI(TAG_MAIN, "Waiting for STA connection...");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

    ESP_LOGI(TAG_MAIN, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG_MAIN, "║  ✓ CardRepeater Ready!               ║");
    ESP_LOGI(TAG_MAIN, "║  Connect to: %-24s║", stored_config.ap_ssid);
    ESP_LOGI(TAG_MAIN, "║  Config IP: %-26s║", ap_ip_str);
    ESP_LOGI(TAG_MAIN, "║  NAT Status: %-24s║", napt_enabled ? "ENABLED" : "PENDING");
    ESP_LOGI(TAG_MAIN, "╚═══════════════════════════════════════╝");
  }
}
