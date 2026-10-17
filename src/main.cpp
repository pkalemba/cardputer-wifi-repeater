/*
 * ESP-IDF WiFi Repeater with NAPT (Network Address Port Translation)
 * Based on official ESP-IDF softap_sta example
 *
 * This creates a WiFi repeater that:
 * - Connects to an upstream WiFi network (Station mode)
 * - Provides an Access Point for clients
 * - Routes traffic between them using NAPT
 * - Optionally tunnels all client traffic through WireGuard
 * - Detects captive portals on the uplink network
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
#include "dhcpserver/dhcpserver.h"
#include "esp_netif_sntp.h"
#include "esp_http_client.h"

// WireGuard
#include "esp_wireguard.h"

// Display includes
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"

// Web server includes
#include "esp_http_server.h"

/* WiFi Configuration - Dynamic (loaded from NVS) */
#define WIFI_STA_MAXIMUM_RETRY 10
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

/* WireGuard defaults */
#define WG_DEFAULT_PORT 51820
#define WG_DEFAULT_KEEPALIVE 25
#define WG_KEY_B64_LEN 44 // base64 of a 32 byte key

/* Configuration storage */
typedef struct
{
  char sta_ssid[32];
  char sta_password[64];
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
} repeater_config_t;

static repeater_config_t stored_config = {0};

/* FreeRTOS event group to signal when we are connected */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

/* DHCP server option */
#define DHCPS_OFFER_DNS 0x02

/* Logging tags */
static const char *TAG_AP = "WiFi AP";
static const char *TAG_STA = "WiFi STA";
static const char *TAG_MAIN = "WiFi Repeater";

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

/* Network interface handles */
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;

/* Uplink connectivity state (result of the captive portal probe) */
typedef enum
{
  UPLINK_OFFLINE,  // No STA connection or no response
  UPLINK_CHECKING, // Connected, probe pending
  UPLINK_PORTAL,   // Captive portal intercepts traffic - login required
  UPLINK_ONLINE    // Real internet access confirmed
} uplink_state_t;

/* Captive portal probe: returns HTTP 204 only with real internet access */
#define CONNECTIVITY_CHECK_URL "http://connectivitycheck.gstatic.com/generate_204"
#define PORTAL_FALLBACK_URL "http://neverssl.com/"

/* Status tracking */
static bool sta_connected = false;
static bool napt_enabled = false;
static uplink_state_t uplink_state = UPLINK_OFFLINE;
static char portal_url[256] = {0};

/* WireGuard state */
static wireguard_config_t wg_config = {};
static wireguard_ctx_t wg_ctx = {};
static char wg_ip[16] = {0};
static char wg_netmask[16] = {0};
static bool wg_initialized = false;
static bool wg_connected = false;
static bool wg_peer_up = false;
static bool wg_is_default = false;

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

/* Web Server Configuration */
#define WEB_SERVER_STACK_SIZE 8192

/* Display handles */
static esp_lcd_panel_io_handle_t lcd_io_handle = NULL;
static esp_lcd_panel_handle_t lcd_panel_handle = NULL;
static int ap_client_count = 0;

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
    "button{background:#4CAF50;color:white;padding:12px 20px;border:none;border-radius:4px;cursor:pointer;width:100%;font-size:16px}"
    "button:hover{background:#45a049}"
    ".row{display:flex;gap:8px}.row input{flex:1}.row button{width:auto;padding:8px 14px;margin-bottom:15px;font-size:14px}"
    ".net{padding:8px;margin:0 0 4px;background:#e8f5e9;border-radius:4px;cursor:pointer;font-size:14px}"
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
    "function scan(){"
    "var n=document.getElementById('nets');n.textContent='Scanning...';"
    "fetch('/scan').then(function(r){if(!r.ok)throw r.status;return r.json()}).then(function(l){"
    "n.textContent='';"
    "if(!l.length){n.textContent='No networks found';return}"
    "l.forEach(function(a){var d=document.createElement('div');d.className='net';"
    "d.textContent=(a.auth?'\\uD83D\\uDD12 ':'')+a.ssid+'  ('+a.rssi+' dBm, ch '+a.ch+')';"
    "d.onclick=function(){document.getElementById('sta_ssid').value=a.ssid;n.textContent=''};"
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
  }
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

  httpd_resp_sendstr_chunk(req,
                           "<form action='/save' method='POST'>"
                           "<div class='section'>"
                           "<h2 style='color:#4CAF50;margin-top:0'>Uplink WiFi</h2>"
                           "<label>Network Name (SSID):</label>"
                           "<div class='row'><input type='text' id='sta_ssid' name='sta_ssid' value='");
  send_html_escaped(req, config->sta_ssid);
  httpd_resp_sendstr_chunk(req,
                           "' placeholder='Your WiFi network name' required>"
                           "<button type='button' onclick='scan()'>Scan</button></div>"
                           "<div id='nets'></div>"
                           "<label>Password:</label>"
                           "<input type='password' name='sta_pass' placeholder='");
  httpd_resp_sendstr_chunk(req, strlen(config->sta_password) > 0 ? "Leave blank to keep current" : "WiFi password");
  httpd_resp_sendstr_chunk(req,
                           "'></div>"
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
                           "<div class='info'>The tunnel uses AllowedIPs 0.0.0.0/0. Traffic switches to the VPN "
                           "after a successful handshake and while the uplink has internet access "
                           "(not during captive portal login).</div>"
                           "</div>"
                           "<button type='submit'>Save & Restart</button>"
                           "</form>"
                           "<div class='status warn'>Device will restart after saving configuration</div>");
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
 * WEB SERVER HTTP HANDLERS
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Root page handler - serves configuration form
 */
static esp_err_t root_handler(httpd_req_t *req)
{
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
  char *body = (char *)malloc(1536);
  if (!body)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
    return ESP_FAIL;
  }

  if (!read_post_body(req, body, 1536))
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

  // Parse password, but only update if not empty
  char temp_pass[64] = {0};
  if (!error && parse_query_param(body, "sta_pass", temp_pass, sizeof(temp_pass)) && strlen(temp_pass) > 0)
  {
    strncpy(new_config.sta_password, temp_pass, sizeof(new_config.sta_password));
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
  parse_query_param(body, "wg_peer", new_config.wg_peer_public_key, sizeof(new_config.wg_peer_public_key));
  parse_query_param(body, "wg_host", new_config.wg_endpoint, sizeof(new_config.wg_endpoint));
  parse_query_param(body, "wg_dns", new_config.wg_dns, sizeof(new_config.wg_dns));

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_priv", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    strncpy(new_config.wg_private_key, temp, sizeof(new_config.wg_private_key) - 1);
  }

  memset(temp, 0, sizeof(temp));
  if (parse_query_param(body, "wg_psk", temp, sizeof(temp)) && strlen(temp) > 0)
  {
    if (strcmp(temp, "-") == 0)
      memset(new_config.wg_preshared_key, 0, sizeof(new_config.wg_preshared_key));
    else
      strncpy(new_config.wg_preshared_key, temp, sizeof(new_config.wg_preshared_key) - 1);
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

  free(body);

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
static esp_err_t scan_handler(httpd_req_t *req)
{
  wifi_scan_config_t scan_config = {};
  scan_config.show_hidden = false;

  ESP_LOGI(TAG_STA, "Scanning for networks...");
  esp_err_t err = esp_wifi_scan_start(&scan_config, true);
  if (err != ESP_OK)
  {
    // e.g. ESP_ERR_WIFI_STATE while the station is busy connecting
    ESP_LOGW(TAG_STA, "Scan failed: %s", esp_err_to_name(err));
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_sendstr(req, esp_err_to_name(err));
    return ESP_OK;
  }

  uint16_t count = WIFI_SCAN_MAX_APS;
  wifi_ap_record_t *records = (wifi_ap_record_t *)calloc(WIFI_SCAN_MAX_APS, sizeof(wifi_ap_record_t));
  if (!records)
  {
    esp_wifi_clear_ap_list();
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
    return ESP_FAIL;
  }
  esp_wifi_scan_get_ap_records(&count, records);
  ESP_LOGI(TAG_STA, "Scan found %d networks", count);

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
             records[i].authmode == WIFI_AUTH_OPEN ? "false" : "true");
    httpd_resp_sendstr_chunk(req, fields);
    first = false;
  }
  httpd_resp_sendstr_chunk(req, "]");
  httpd_resp_sendstr_chunk(req, NULL);

  free(records);
  return ESP_OK;
}

/**
 * Catch-all handler - redirects to the config page.
 * Together with the DNS server in setup mode this makes phones and laptops
 * open the configuration page automatically (captive portal).
 */
static esp_err_t captive_redirect_handler(httpd_req_t *req)
{
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "http://" WEB_CONFIG_IP "/");
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

    // Must be registered last - matches everything
    httpd_uri_t captive = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = captive_redirect_handler,
        .user_ctx = NULL};
    httpd_register_uri_handler(web_server, &captive);

    ESP_LOGI(TAG_MAIN, "✓ Web server started successfully");
    ESP_LOGI(TAG_MAIN, "  Access at: http://192.168.4.1/");

    return web_server;
  }

  ESP_LOGE(TAG_MAIN, "✗ Failed to start web server");
  return NULL;
}

/**
 * Captive portal DNS server (setup mode only).
 * Answers every A query with the AP address so any hostname leads to the config page.
 */
static void captive_dns_task(void *pvParameters)
{
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
  {
    ESP_LOGE(TAG_MAIN, "DNS: failed to create socket");
    vTaskDelete(NULL);
    return;
  }

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    ESP_LOGE(TAG_MAIN, "DNS: failed to bind port 53");
    close(sock);
    vTaskDelete(NULL);
    return;
  }

  esp_netif_ip_info_t ip_info;
  esp_netif_get_ip_info(ap_netif, &ip_info);
  ESP_LOGI(TAG_MAIN, "✓ Captive portal DNS started (all names -> " IPSTR ")", IP2STR(&ip_info.ip));

  uint8_t buf[512];
  while (1)
  {
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    // Leave room for the 16 byte answer record
    int len = recvfrom(sock, buf, sizeof(buf) - 16, 0, (struct sockaddr *)&client, &client_len);

    // Only standard queries (QR=0, OPCODE=0) with exactly one question
    if (len < 12 || (buf[2] & 0x80) || (buf[2] & 0x78) || buf[4] != 0 || buf[5] != 1)
      continue;

    // Skip QNAME labels
    int pos = 12;
    while (pos < len && buf[pos] != 0)
      pos += buf[pos] + 1;
    if (pos + 5 > len)
      continue;
    uint16_t qtype = (buf[pos + 1] << 8) | buf[pos + 2];
    int resp_len = pos + 5; // drop any additional records (EDNS)

    bool answer = (qtype == 1 /* A */ || qtype == 255 /* ANY */);
    buf[2] = 0x84 | (buf[2] & 0x01); // QR, AA, keep RD
    buf[3] = 0x80;                   // RA, NOERROR
    buf[6] = 0;
    buf[7] = answer ? 1 : 0; // ANCOUNT
    memset(&buf[8], 0, 4);   // NSCOUNT, ARCOUNT

    if (answer)
    {
      const uint8_t record[12] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04};
      memcpy(&buf[resp_len], record, sizeof(record));
      memcpy(&buf[resp_len + 12], &ip_info.ip.addr, 4);
      resp_len += 16;
    }

    sendto(sock, buf, resp_len, 0, (struct sockaddr *)&client, client_len);
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
 * Update Display with beautiful visual UI
 */
static void display_update_status(void)
{
  if (!framebuffer)
    return;

  // Clear screen with pure black background (terminal style)
  lcd_fill_screen(TERM_BG);

  // ═══════════════════════════════════════════════════════════
  // HEADER with Title - Terminal style
  // ═══════════════════════════════════════════════════════════
  lcd_fill_rect(0, 0, 240, 16, TERM_GREEN_DARK);
  lcd_draw_string(30, 4, "Card Wifi Repeater", TERM_GREEN, TERM_GREEN_DARK);

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
      lcd_draw_string(6, uplink_y + 14, stored_config.sta_ssid, TERM_ACCENT, TERM_BG);

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
      const char *vpn_str = wg_is_default ? "VPN:ON" : (wg_peer_up ? "VPN:RDY" : "VPN:..");
      lcd_draw_string(176, uplink_y + 27, vpn_str, wg_is_default ? TERM_GREEN : TERM_GREEN_DIM, TERM_BG);
    }
  }
  else
  {
    // Disconnected state
    lcd_draw_string(6, uplink_y + 14, "Searching...", TERM_GREEN_DIM, TERM_BG);
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
    lcd_draw_string(56, config_y + 5, WEB_CONFIG_IP, TERM_GREEN, TERM_BG);
  }

  // Flush to display
  lcd_flush();
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
 * Forward DNS settings from STA interface to AP's DHCP server
 * (or offer the configured VPN DNS when WireGuard is enabled)
 */
static void setup_dns_forwarding(void)
{
  if (!sta_netif || !ap_netif)
  {
    ESP_LOGE(TAG_MAIN, "Network interfaces not initialized");
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

/**
 * Check internet connectivity and detect captive portals.
 *
 * Requests a URL that returns an empty HTTP 204 on a free internet
 * connection. A redirect or any other answer means a captive portal
 * intercepts traffic. The request is bound to the uplink interface so
 * the result is independent of the WireGuard tunnel.
 */
static void check_internet_connectivity(void)
{
  if (!sta_connected)
  {
    uplink_state = UPLINK_OFFLINE;
    return;
  }

  ESP_LOGI(TAG_MAIN, "Checking internet connectivity...");

  struct ifreq ifr = {};
  esp_netif_get_netif_impl_name(sta_netif, ifr.ifr_name);

  char location[sizeof(portal_url)] = {0};
  esp_http_client_config_t config = {};
  config.url = CONNECTIVITY_CHECK_URL;
  config.timeout_ms = 5000;
  config.disable_auto_redirect = true;
  config.event_handler = probe_http_event_handler;
  config.user_data = location;
  config.if_name = &ifr;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client)
  {
    ESP_LOGE(TAG_MAIN, "Failed to create HTTP client");
    uplink_state = UPLINK_OFFLINE;
    return;
  }

  esp_err_t err = esp_http_client_perform(client);
  int status = esp_http_client_get_status_code(client);
  esp_http_client_cleanup(client);

  if (err != ESP_OK)
  {
    ESP_LOGW(TAG_MAIN, "✗ No internet connectivity (%s)", esp_err_to_name(err));
    uplink_state = UPLINK_OFFLINE;
  }
  else if (status == 204)
  {
    ESP_LOGI(TAG_MAIN, "✓ Internet connectivity confirmed");
    uplink_state = UPLINK_ONLINE;
    portal_url[0] = '\0';
  }
  else
  {
    strlcpy(portal_url, location, sizeof(portal_url));
    ESP_LOGW(TAG_MAIN, "⚠ Captive portal detected (HTTP %d) - login at: %s",
             status, strlen(portal_url) > 0 ? portal_url : PORTAL_FALLBACK_URL);
    uplink_state = UPLINK_PORTAL;
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * WIREGUARD VPN
 * ═══════════════════════════════════════════════════════════════════ */

/* lwIP is not thread safe - these run inside the TCP/IP task */
static esp_err_t wg_init_cb(void *ctx) { return esp_wireguard_init(&wg_config, (wireguard_ctx_t *)ctx); }
static esp_err_t wg_connect_cb(void *ctx) { return esp_wireguard_connect((wireguard_ctx_t *)ctx); }
static esp_err_t wg_disconnect_cb(void *ctx) { return esp_wireguard_disconnect((wireguard_ctx_t *)ctx); }
static esp_err_t wg_peer_is_up_cb(void *ctx) { return esp_wireguard_peer_is_up((wireguard_ctx_t *)ctx); }
static esp_err_t wg_set_default_cb(void *ctx) { return esp_wireguard_set_default((wireguard_ctx_t *)ctx); }
static esp_err_t wg_restore_default_cb(void *ctx) { return esp_wireguard_restore_default((wireguard_ctx_t *)ctx); }
static esp_err_t wg_allow_all_cb(void *ctx)
{
  // Full tunnel: accept and route any address through the peer
  return esp_wireguard_add_allowed_ip((wireguard_ctx_t *)ctx, "0.0.0.0", "0.0.0.0");
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
    if (uplink_state != UPLINK_ONLINE || !wg_sync_time())
      return;

    if (!wg_initialized)
    {
      if (!parse_cidr(stored_config.wg_address, wg_ip, sizeof(wg_ip), wg_netmask, sizeof(wg_netmask)))
      {
        ESP_LOGE(TAG_MAIN, "WireGuard: invalid address %s", stored_config.wg_address);
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
      wg_connected = true;
      ESP_LOGI(TAG_MAIN, "WireGuard: connecting to %s:%d", stored_config.wg_endpoint, stored_config.wg_port);
    }
    else if (err != ESP_ERR_RETRY)
    {
      ESP_LOGE(TAG_MAIN, "WireGuard: connect failed: %s", esp_err_to_name(err));
      // Reset the interface so the next attempt starts clean
      if (wg_ctx.netif)
        esp_netif_tcpip_exec(wg_disconnect_cb, &wg_ctx);
    }
    return;
  }

  wg_peer_up = esp_netif_tcpip_exec(wg_peer_is_up_cb, &wg_ctx) == ESP_OK;

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
    display_update_status();
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
    display_update_status();
  }

  /* Station Events */
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
  {
    // In setup mode the station only exists for WiFi scanning
    if (!config_mode)
    {
      ESP_LOGI(TAG_STA, "Station started, connecting to AP...");
      esp_wifi_connect();
    }
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
  {
    if (s_retry_num < WIFI_STA_MAXIMUM_RETRY)
    {
      esp_wifi_connect();
      s_retry_num++;
      ESP_LOGI(TAG_STA, "Retry connecting to AP... (%d/%d)", s_retry_num, WIFI_STA_MAXIMUM_RETRY);
    }
    else
    {
      xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
      ESP_LOGE(TAG_STA, "Failed to connect to AP after %d attempts", WIFI_STA_MAXIMUM_RETRY);
    }
    sta_connected = false;
    uplink_state = UPLINK_OFFLINE;
    display_update_status();
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
  {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG_STA, "✓ Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    s_retry_num = 0;
    sta_connected = true;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

    /* Configure DNS and enable NAPT after getting IP */
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

    display_update_status();
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

  wifi_config_t wifi_sta_config = {};

  /* Configure STA settings */
  memcpy(wifi_sta_config.sta.ssid, stored_config.sta_ssid, strlen(stored_config.sta_ssid));
  memcpy(wifi_sta_config.sta.password, stored_config.sta_password, strlen(stored_config.sta_password));
  wifi_sta_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  wifi_sta_config.sta.failure_retry_cnt = WIFI_STA_MAXIMUM_RETRY;
  wifi_sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  wifi_sta_config.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config));

  ESP_LOGI(TAG_STA, "✓ Station configured: connecting to SSID=%s", stored_config.sta_ssid);
}

/**
 * Status monitoring task - connectivity / captive portal checks and WireGuard
 */
static void status_task(void *pvParameters)
{
  while (1)
  {
    if (sta_connected)
    {
      // Check internet connectivity periodically
      check_internet_connectivity();
      wireguard_update();

      wifi_ap_record_t ap_info;
      if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
      {
        ESP_LOGI(TAG_MAIN, "━━━ STATUS ━━━");
        ESP_LOGI(TAG_MAIN, "Uplink: %s | RSSI: %d dBm",
                 stored_config.sta_ssid, ap_info.rssi);
        ESP_LOGI(TAG_MAIN, "AP Clients: %d", ap_client_count);
        ESP_LOGI(TAG_MAIN, "NAT: %s", napt_enabled ? "✓ ACTIVE" : "✗ DISABLED");
        ESP_LOGI(TAG_MAIN, "Internet: %s",
                 uplink_state == UPLINK_ONLINE ? "✓ ONLINE" : (uplink_state == UPLINK_PORTAL ? "⚠ CAPTIVE PORTAL" : "✗ OFFLINE"));
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

    // Update display
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
    stored_config.configured = false;
    config_mode = true;

    // Show on display
    if (framebuffer)
    {
      lcd_fill_screen(TERM_BG);
      lcd_fill_rect(0, 0, 240, 18, TERM_GREEN_DARK);
      lcd_draw_string(40, 5, "SETUP MODE", TERM_GREEN, TERM_GREEN_DARK);

      lcd_draw_string(5, 30, "WiFi:", TERM_GREEN_DIM, TERM_BG);
      lcd_draw_string(5, 45, DEFAULT_CONFIG_AP_SSID, TERM_ACCENT, TERM_BG);

      lcd_draw_string(5, 65, "Config IP:", TERM_GREEN_DIM, TERM_BG);
      lcd_draw_string(5, 80, WEB_CONFIG_IP, TERM_GREEN, TERM_BG);

      lcd_draw_string(5, 100, "Open browser and", TERM_GREEN_DIM, TERM_BG);
      lcd_draw_string(5, 113, "visit IP above", TERM_GREEN_DIM, TERM_BG);
      lcd_flush();
    }
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

    /* Create status monitoring task before WiFi starts so it gets notified on connect */
    xTaskCreate(status_task, "status_task", 8192, NULL, 5, &status_task_handle);

    /* Start WiFi */
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG_MAIN, "✓ WiFi started in AP+STA mode");

    /* Start web server right away - also reachable when the uplink fails,
     * so the uplink can be fixed via WiFi scan */
    vTaskDelay(pdMS_TO_TICKS(1000));
    start_webserver();
    display_update_status();

    /* Wait for connection */
    ESP_LOGI(TAG_MAIN, "Waiting for STA connection...");
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           portMAX_DELAY);

    /* Check connection result */
    if (bits & WIFI_CONNECTED_BIT)
    {
      ESP_LOGI(TAG_MAIN, "╔═══════════════════════════════════════╗");
      ESP_LOGI(TAG_MAIN, "║  ✓ CardRepeater Ready!               ║");
      ESP_LOGI(TAG_MAIN, "║  Connect to: %-24s║", stored_config.ap_ssid);
      ESP_LOGI(TAG_MAIN, "║  Config IP: %-26s║", WEB_CONFIG_IP);
      ESP_LOGI(TAG_MAIN, "║  NAT Status: %-24s║", napt_enabled ? "ENABLED" : "PENDING");
      ESP_LOGI(TAG_MAIN, "╚═══════════════════════════════════════╝");
    }
    else if (bits & WIFI_FAIL_BIT)
    {
      ESP_LOGE(TAG_MAIN, "✗ Failed to connect to SSID:%s", stored_config.sta_ssid);
    }
    else
    {
      ESP_LOGE(TAG_MAIN, "✗ Unexpected event");
    }
  }
}
