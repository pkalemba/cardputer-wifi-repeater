/*
 * On-device WiFi menu: keyboard map of the Cardputer ADV and the menu
 * state machine (pick a network, type its password). No hardware
 * dependencies - drawing and WiFi calls are done by main.cpp, the logic is
 * unit tested on the host (test/host).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════
 * Keyboard (TCA8418 key numbers -> key codes)
 * ═══════════════════════════════════════════════════════════════════ */

/* Printable keys give their ASCII code, the others these codes */
#define KC_NONE 0x00
#define KC_BACKSPACE 0x08
#define KC_TAB 0x09
#define KC_ENTER 0x0D
#define KC_ESC 0x1B
#define KC_UP 0x81
#define KC_DOWN 0x82
#define KC_LEFT 0x83
#define KC_RIGHT 0x84
#define KC_SHIFT 0x90
#define KC_FN 0x91
#define KC_CTRL 0x92
#define KC_OPT 0x93
#define KC_ALT 0x94

/*
 * Position on the 4x14 keyboard (row 0 = number row, column 0 = left) of a
 * TCA8418 key number (row * 10 + column + 1 of its 7x8 matrix, as wired on
 * the Cardputer ADV). False for numbers outside the matrix.
 */
bool keyboard_key_position(uint8_t key_number, int *row, int *column);

/*
 * Key code of a key number with the shift / fn modifiers held. fn gives the
 * arrows on ; . , / and Esc on the ` key.
 */
uint8_t keyboard_key_code(uint8_t key_number, bool shift, bool fn);

/* ═══════════════════════════════════════════════════════════════════
 * WiFi menu
 * ═══════════════════════════════════════════════════════════════════ */

#define MENU_MAX_NETWORKS 20
#define MENU_VISIBLE_ROWS 7
#define MENU_PASSWORD_MIN 8 // WPA2 passphrases are 8-63 characters
#define MENU_PASSWORD_MAX 63

typedef enum
{
  MENU_CLOSED,
  MENU_SCANNING, // waiting for the scan results
  MENU_LIST,     // pick a network
  MENU_PASSWORD, // type the password of a secured network
} menu_screen_t;

typedef enum
{
  MENU_ACT_NONE,    // key ignored
  MENU_ACT_REDRAW,  // state changed, redraw the menu
  MENU_ACT_SCAN,    // start a scan, then call wifi_menu_scan_done()
  MENU_ACT_CONNECT, // connect to wifi_menu_selected() with menu->password (or the saved one)
  MENU_ACT_CLOSE,   // menu closed, back to the status screen
} menu_action_t;

typedef struct
{
  char ssid[33];
  int8_t rssi;
  bool secured;
  bool saved; // already saved (with its password)
} menu_network_t;

typedef struct
{
  menu_screen_t screen;
  menu_network_t networks[MENU_MAX_NETWORKS];
  int count;
  int selected;
  int scroll; // first visible row
  char password[MENU_PASSWORD_MAX + 1];
  int password_len;
  bool password_entered; // false: connect with the saved password
} wifi_menu_t;

/* Open the menu: the caller scans next (returns MENU_ACT_SCAN) */
menu_action_t wifi_menu_open(wifi_menu_t *menu);

/*
 * Add a scan result (call in RSSI order between open/rescan and
 * wifi_menu_scan_done). Hidden and duplicate names are skipped. False when
 * the result was not added.
 */
bool wifi_menu_add_network(wifi_menu_t *menu, const char *ssid, int rssi, bool secured, bool saved);

/* Scan finished: show the list */
void wifi_menu_scan_done(wifi_menu_t *menu);

/* Handle a key code (keyboard_key_code) */
menu_action_t wifi_menu_key(wifi_menu_t *menu, uint8_t key);

/* The highlighted network, NULL when the list is empty */
const menu_network_t *wifi_menu_selected(const wifi_menu_t *menu);
