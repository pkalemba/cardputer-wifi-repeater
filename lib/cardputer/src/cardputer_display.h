/*
 * M5Stack Cardputer display: ST7789 (240x135, landscape) with a
 * framebuffer, an 8x8 font and the Gruvbox dark theme shared by all apps.
 *
 * Drawing goes to the framebuffer, lcd_flush() sends it to the panel.
 * Apps that draw from several tasks wrap draw + flush in
 * display_lock() / display_unlock() (recursive).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define LCD_V_RES 240 // framebuffer width (landscape)
#define LCD_H_RES 136 // framebuffer height (the panel shows 135 rows)
#define FONT_W 8
#define FONT_H 8

/* RGB565, byte-swapped for the ST7789 */
#define RGB565(r, g, b) ({                                              \
  uint16_t rgb = ((((r) >> 3) << 11) | (((g) >> 2) << 5) | ((b) >> 3)); \
  (uint16_t)((rgb >> 8) | (rgb << 8));                                  \
})
/* The panel is set up as BGR, so RGB565() takes the channels the other way
 * round - DISPLAY_RGB() takes a normal R, G, B color */
#define DISPLAY_RGB(r, g, b) RGB565(b, g, r)

/* Gruvbox dark - the same palette as the repeater's web panel */
#define GRUV_BG0 DISPLAY_RGB(0x28, 0x28, 0x28)
#define GRUV_BG1 DISPLAY_RGB(0x3c, 0x38, 0x36)
#define GRUV_BG2 DISPLAY_RGB(0x50, 0x49, 0x45)
#define GRUV_BG3 DISPLAY_RGB(0x66, 0x5c, 0x54)
#define GRUV_FG DISPLAY_RGB(0xeb, 0xdb, 0xb2)
#define GRUV_FG4 DISPLAY_RGB(0xa8, 0x99, 0x84)
#define GRUV_YELLOW DISPLAY_RGB(0xfa, 0xbd, 0x2f)
#define GRUV_GREEN DISPLAY_RGB(0xb8, 0xbb, 0x26)
#define GRUV_ORANGE DISPLAY_RGB(0xfe, 0x80, 0x19)
#define GRUV_RED DISPLAY_RGB(0xfb, 0x49, 0x34)
#define GRUV_AQUA DISPLAY_RGB(0x8e, 0xc0, 0x7c)

/* Colors by role */
#define THEME_BG GRUV_BG0       // background
#define THEME_BAR GRUV_BG1      // title bars, selected rows
#define THEME_BORDER GRUV_BG3   // box borders
#define THEME_TITLE GRUV_YELLOW // titles and labels
#define THEME_TEXT GRUV_FG      // values
#define THEME_DIM GRUV_FG4      // secondary text
#define THEME_OK GRUV_GREEN     // online, good signal, battery
#define THEME_CHECKING GRUV_YELLOW
#define THEME_PORTAL GRUV_ORANGE
#define THEME_WARNING GRUV_ORANGE
#define THEME_ERROR GRUV_RED

/* Arrows for key hints, at their CP437 codes */
#define CHAR_UP "\x18"
#define CHAR_DOWN "\x19"
#define CHAR_RIGHT "\x1A"
#define CHAR_LEFT "\x1B"

/*
 * SPI bus, panel and framebuffer. The backlight stays off until
 * lcd_backlight(true), so the first screen can be drawn first. False when
 * the framebuffer could not be allocated (drawing is then a no-op).
 */
bool lcd_init(void);
bool lcd_ready(void);

void display_lock(void);
void display_unlock(void);

void lcd_backlight(bool on);
void lcd_flush(void);

void lcd_fill_screen(uint16_t color);
void lcd_fill_rect(int x, int y, int w, int h, uint16_t color);
void lcd_fill_circle(int x, int y, int radius, uint16_t color);
void lcd_draw_char(int x, int y, char c, uint16_t color, uint16_t bg_color);
void lcd_draw_string(int x, int y, const char *str, uint16_t color, uint16_t bg_color);

/* ═══════════════════════════════════════════════════════════════════
 * Widgets
 * ═══════════════════════════════════════════════════════════════════ */

/* One pixel frame in the border color */
void ui_draw_frame(int x, int y, int w, int h);

/* Title bar (18 px) with the battery on the right */
void ui_draw_title_bar(const char *title);

/* Battery level (percentage and icon) right-aligned at right_x; nothing while unknown */
void ui_draw_battery(int right_x, int y, uint16_t bg_color);

/* Signal strength as 1-4 bars (15x8 px) */
void ui_draw_signal_bars(int x, int y, int rssi);

/* Horizontal meter for an RSSI between -100 and -30 dBm (for finding a device) */
void ui_draw_rssi_meter(int x, int y, int w, int h, int rssi, uint16_t color);
