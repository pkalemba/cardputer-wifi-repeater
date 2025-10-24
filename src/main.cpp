/*
 * ESP-IDF WiFi Repeater with NAPT (Network Address Port Translation)
 * Based on official ESP-IDF softap_sta example
 *
 * This creates a WiFi repeater that:
 * - Connects to an upstream WiFi network (Station mode)
 * - Provides an Access Point for clients
 * - Routes traffic between them using NAPT
 */

#include <string.h>
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
#include "dhcpserver/dhcpserver.h"

// Display includes
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"

/* WiFi Configuration */
#define WIFI_STA_SSID "weeblet"
#define WIFI_STA_PASSWORD "niconiconii"
#define WIFI_STA_MAXIMUM_RETRY 10

#define WIFI_AP_SSID "NINTENDO_WIFI"
#define WIFI_AP_PASSWORD "" // Empty = Open network
#define WIFI_AP_CHANNEL 1
#define WIFI_AP_MAX_CONNECTIONS 10

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

/* Status tracking */
static bool sta_connected = false;
static bool napt_enabled = false;

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

/* Display handles */
static esp_lcd_panel_io_handle_t lcd_io_handle = NULL;
static esp_lcd_panel_handle_t lcd_panel_handle = NULL;
static int ap_client_count = 0;

/**
 * RGB565 Color definitions (with byte swap for ST7789)
 */
#define RGB565(r, g, b) ((((r & 0xF8) | (g >> 5)) << 8) | (((g & 0x1C) << 3) | (b >> 3)))
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
      .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
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

  ESP_LOGI(TAG_MAIN, "Framebuffer: %p, Size: %d bytes", framebuffer, LCD_V_RES * LCD_H_RES * 2);
  ESP_LOGI(TAG_MAIN, "Display resolution: %dx%d (WxH after rotation)", LCD_V_RES, LCD_H_RES);

  // Use raw RGB565 values to test
  ESP_LOGI(TAG_MAIN, "Test 1: WHITE screen (0xFFFF)");
  for (int i = 0; i < LCD_V_RES * LCD_H_RES; i++)
  {
    framebuffer[i] = 0xFFFF;
  }
  esp_lcd_panel_draw_bitmap(lcd_panel_handle, 0, 0, LCD_V_RES, LCD_H_RES, framebuffer);
  vTaskDelay(pdMS_TO_TICKS(2000));

  ESP_LOGI(TAG_MAIN, "Test 2: RED screen (0xF800)");
  for (int i = 0; i < LCD_V_RES * LCD_H_RES; i++)
  {
    framebuffer[i] = 0xF800;
  }
  esp_lcd_panel_draw_bitmap(lcd_panel_handle, 0, 0, LCD_V_RES, LCD_H_RES, framebuffer);
  vTaskDelay(pdMS_TO_TICKS(2000));

  ESP_LOGI(TAG_MAIN, "Test 3: GREEN screen (0x07E0)");
  for (int i = 0; i < LCD_V_RES * LCD_H_RES; i++)
  {
    framebuffer[i] = 0x07E0;
  }
  esp_lcd_panel_draw_bitmap(lcd_panel_handle, 0, 0, LCD_V_RES, LCD_H_RES, framebuffer);
  vTaskDelay(pdMS_TO_TICKS(2000));

  ESP_LOGI(TAG_MAIN, "Test 4: BLUE screen (0x001F)");
  for (int i = 0; i < LCD_V_RES * LCD_H_RES; i++)
  {
    framebuffer[i] = 0x001F;
  }
  esp_lcd_panel_draw_bitmap(lcd_panel_handle, 0, 0, LCD_V_RES, LCD_H_RES, framebuffer);
  vTaskDelay(pdMS_TO_TICKS(2000));

  ESP_LOGI(TAG_MAIN, "Test 5: Text");
  lcd_fill_screen(0x0000);                                  // Black
  lcd_draw_string(10, 10, "WiFi REPEATER", 0xFFFF, 0x0000); // White on black
  lcd_draw_string(10, 30, "Display Test", 0x07E0, 0x0000);  // Green on black
  lcd_flush();

  ESP_LOGI(TAG_MAIN, "Display initialization complete");
}

/**
 * Update Display with current status
 */
static void display_update_status(void)
{
  if (!framebuffer)
    return;

  // Clear screen
  lcd_fill_screen(COLOR_BLACK);

  // Header bar
  lcd_fill_rect(0, 0, LCD_V_RES, 20, COLOR_NAVY);
  lcd_draw_string(50, 6, "WiFi REPEATER", COLOR_YELLOW, COLOR_NAVY);

  int y = 25;

  // Uplink Status
  lcd_draw_string(5, y, "UPLINK:", COLOR_CYAN, COLOR_BLACK);
  y += 12;

  if (sta_connected)
  {
    wifi_ap_record_t ap_info;
    char line[32];

    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
      lcd_draw_string(10, y, WIFI_STA_SSID, COLOR_GREEN, COLOR_BLACK);
      y += 12;

      snprintf(line, sizeof(line), "RSSI:%ddBm", ap_info.rssi);
      lcd_draw_string(10, y, line, COLOR_WHITE, COLOR_BLACK);
      y += 12;
    }

    // Get IP address
    esp_netif_ip_info_t ip_info;
    if (sta_netif && esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK)
    {
      char ip_str[20];
      snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
      lcd_draw_string(10, y, ip_str, COLOR_WHITE, COLOR_BLACK);
      y += 12;
    }
  }
  else
  {
    lcd_draw_string(10, y, "Disconnected", COLOR_RED, COLOR_BLACK);
    y += 12;
  }

  y += 5;

  // Access Point Status
  lcd_draw_string(5, y, "ACCESS POINT:", COLOR_CYAN, COLOR_BLACK);
  y += 12;

  lcd_draw_string(10, y, WIFI_AP_SSID, COLOR_GREEN, COLOR_BLACK);
  y += 12;

  char clients_str[32];
  snprintf(clients_str, sizeof(clients_str), "Clients:%d", ap_client_count);
  lcd_draw_string(10, y, clients_str, COLOR_WHITE, COLOR_BLACK);
  y += 12;

  // NAT Status bar at bottom
  uint16_t nat_color = napt_enabled ? COLOR_DARKGREEN : COLOR_RED;
  lcd_fill_rect(0, LCD_H_RES - 15, LCD_V_RES, 15, nat_color);
  lcd_draw_string(60, LCD_H_RES - 12, napt_enabled ? "NAT ACTIVE" : "NAT DISABLED", COLOR_WHITE, nat_color);

  // Flush to display
  lcd_flush();
}

/**
 * Forward DNS settings from STA interface to AP's DHCP server
 */
static void setup_dns_forwarding(void)
{
  if (!sta_netif || !ap_netif)
  {
    ESP_LOGE(TAG_MAIN, "Network interfaces not initialized");
    return;
  }

  esp_netif_dns_info_t dns;
  esp_err_t err = esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns);

  if (err == ESP_OK)
  {
    ESP_LOGI(TAG_MAIN, "Forwarding DNS: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));

    // Stop DHCP server
    esp_netif_dhcps_stop(ap_netif);

    // Enable DNS option
    uint8_t dhcps_offer_option = DHCPS_OFFER_DNS;
    esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                           &dhcps_offer_option, sizeof(dhcps_offer_option));

    // Set DNS info
    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);

    // Restart DHCP server
    esp_netif_dhcps_start(ap_netif);

    ESP_LOGI(TAG_MAIN, "DNS forwarding configured successfully");
  }
  else
  {
    ESP_LOGE(TAG_MAIN, "Failed to get DNS info from STA interface");
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
    ESP_LOGI(TAG_STA, "Station started, connecting to AP...");
    esp_wifi_connect();
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
  memcpy(wifi_ap_config.ap.ssid, WIFI_AP_SSID, strlen(WIFI_AP_SSID));
  wifi_ap_config.ap.ssid_len = strlen(WIFI_AP_SSID);
  memcpy(wifi_ap_config.ap.password, WIFI_AP_PASSWORD, strlen(WIFI_AP_PASSWORD));
  wifi_ap_config.ap.channel = WIFI_AP_CHANNEL;
  wifi_ap_config.ap.max_connection = WIFI_AP_MAX_CONNECTIONS;

  /* Set auth mode based on password */
  if (strlen(WIFI_AP_PASSWORD) > 0)
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
           WIFI_AP_SSID, WIFI_AP_CHANNEL,
           strlen(WIFI_AP_PASSWORD) > 0 ? "WPA2" : "OPEN");
}

/**
 * Initialize WiFi Station
 */
static void wifi_init_sta(void)
{
  sta_netif = esp_netif_create_default_wifi_sta();

  wifi_config_t wifi_sta_config = {};

  /* Configure STA settings */
  memcpy(wifi_sta_config.sta.ssid, WIFI_STA_SSID, strlen(WIFI_STA_SSID));
  memcpy(wifi_sta_config.sta.password, WIFI_STA_PASSWORD, strlen(WIFI_STA_PASSWORD));
  wifi_sta_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  wifi_sta_config.sta.failure_retry_cnt = WIFI_STA_MAXIMUM_RETRY;
  wifi_sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  wifi_sta_config.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config));

  ESP_LOGI(TAG_STA, "✓ Station configured: connecting to SSID=%s", WIFI_STA_SSID);
}

/**
 * Status monitoring task
 */
static void status_task(void *pvParameters)
{
  while (1)
  {
    if (sta_connected)
    {
      wifi_ap_record_t ap_info;
      if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
      {
        ESP_LOGI(TAG_MAIN, "━━━ STATUS ━━━");
        ESP_LOGI(TAG_MAIN, "Uplink: %s | RSSI: %d dBm",
                 WIFI_STA_SSID, ap_info.rssi);
        ESP_LOGI(TAG_MAIN, "AP Clients: %d", ap_client_count);
        ESP_LOGI(TAG_MAIN, "NAT: %s", napt_enabled ? "✓ ACTIVE" : "✗ DISABLED");
        ESP_LOGI(TAG_MAIN, "Repeater: %s",
                 (sta_connected && napt_enabled) ? "✓ READY" : "⧗ INITIALIZING");
      }
    }
    else
    {
      ESP_LOGI(TAG_MAIN, "Waiting for uplink connection...");
    }

    // Update display
    display_update_status();

    vTaskDelay(pdMS_TO_TICKS(5000)); // Update every 5 seconds
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

  /* Initialize NVS - Required for WiFi */
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

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

  /* Set AP+STA mode */
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

  /* Disable power saving for better performance */
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  ESP_LOGI(TAG_MAIN, "✓ Power saving disabled for optimal performance");

  /* Initialize AP and STA */
  wifi_init_softap();
  wifi_init_sta();

  /* Start WiFi */
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_LOGI(TAG_MAIN, "✓ WiFi started in AP+STA mode");

  /* Update display with initial status */
  vTaskDelay(pdMS_TO_TICKS(1000)); // Wait a moment for display
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
    ESP_LOGI(TAG_MAIN, "║  ✓ WiFi Repeater Ready!              ║");
    ESP_LOGI(TAG_MAIN, "║  Connect to: %-24s║", WIFI_AP_SSID);
    ESP_LOGI(TAG_MAIN, "║  NAT Status: %-24s║", napt_enabled ? "ENABLED" : "PENDING");
    ESP_LOGI(TAG_MAIN, "╚═══════════════════════════════════════╝");

    /* Create status monitoring task */
    xTaskCreate(status_task, "status_task", 4096, NULL, 5, NULL);
  }
  else if (bits & WIFI_FAIL_BIT)
  {
    ESP_LOGE(TAG_MAIN, "✗ Failed to connect to SSID:%s", WIFI_STA_SSID);
  }
  else
  {
    ESP_LOGE(TAG_MAIN, "✗ Unexpected event");
  }
}
