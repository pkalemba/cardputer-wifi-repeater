/*
 * On-device WiFi menu - see wifi_menu.h
 */

#include "wifi_menu.h"

#include <stdio.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * Keyboard
 * ═══════════════════════════════════════════════════════════════════ */

/* Same layout as the M5Cardputer library: {normal, shift} per key */
static const uint8_t KEY_MAP[4][14][2] = {
    {{'`', '~'}, {'1', '!'}, {'2', '@'}, {'3', '#'}, {'4', '$'}, {'5', '%'}, {'6', '^'},
     {'7', '&'}, {'8', '*'}, {'9', '('}, {'0', ')'}, {'-', '_'}, {'=', '+'}, {KC_BACKSPACE, KC_BACKSPACE}},
    {{KC_TAB, KC_TAB}, {'q', 'Q'}, {'w', 'W'}, {'e', 'E'}, {'r', 'R'}, {'t', 'T'}, {'y', 'Y'},
     {'u', 'U'}, {'i', 'I'}, {'o', 'O'}, {'p', 'P'}, {'[', '{'}, {']', '}'}, {'\\', '|'}},
    {{KC_FN, KC_FN}, {KC_SHIFT, KC_SHIFT}, {'a', 'A'}, {'s', 'S'}, {'d', 'D'}, {'f', 'F'}, {'g', 'G'},
     {'h', 'H'}, {'j', 'J'}, {'k', 'K'}, {'l', 'L'}, {';', ':'}, {'\'', '"'}, {KC_ENTER, KC_ENTER}},
    {{KC_CTRL, KC_CTRL}, {KC_OPT, KC_OPT}, {KC_ALT, KC_ALT}, {'z', 'Z'}, {'x', 'X'}, {'c', 'C'}, {'v', 'V'},
     {'b', 'B'}, {'n', 'N'}, {'m', 'M'}, {',', '<'}, {'.', '>'}, {'/', '?'}, {' ', ' '}},
};

bool keyboard_key_position(uint8_t key_number, int *row, int *column)
{
  if (key_number < 1 || key_number > 70)
    return false;
  int raw_row = (key_number - 1) / 10;
  int raw_column = (key_number - 1) % 10;
  if (raw_row > 6 || raw_column > 7)
    return false;
  // M5Cardputer library remap of the 7x8 matrix to the 4x14 layout
  *column = raw_row * 2 + (raw_column > 3 ? 1 : 0);
  *row = raw_column % 4;
  return true;
}

uint8_t keyboard_key_code(uint8_t key_number, bool shift, bool fn)
{
  int row, column;
  if (!keyboard_key_position(key_number, &row, &column))
    return KC_NONE;
  uint8_t normal = KEY_MAP[row][column][0];
  if (fn)
  {
    switch (normal)
    {
    case '`':
      return KC_ESC;
    case ';':
      return KC_UP;
    case '.':
      return KC_DOWN;
    case ',':
      return KC_LEFT;
    case '/':
      return KC_RIGHT;
    default:
      break;
    }
  }
  return KEY_MAP[row][column][shift ? 1 : 0];
}

/* ═══════════════════════════════════════════════════════════════════
 * Menu
 * ═══════════════════════════════════════════════════════════════════ */

static void start_scan(wifi_menu_t *menu)
{
  menu->screen = MENU_SCANNING;
  menu->count = 0;
  menu->selected = 0;
  menu->scroll = 0;
}

menu_action_t wifi_menu_open(wifi_menu_t *menu)
{
  memset(menu, 0, sizeof(*menu));
  start_scan(menu);
  return MENU_ACT_SCAN;
}

bool wifi_menu_add_network(wifi_menu_t *menu, const char *ssid, int rssi, bool secured, bool saved)
{
  if (ssid[0] == '\0' || menu->count >= MENU_MAX_NETWORKS)
    return false;
  for (int i = 0; i < menu->count; i++)
    if (strcmp(menu->networks[i].ssid, ssid) == 0)
      return false; // another access point of the same network (weaker - results are sorted)

  menu_network_t *network = &menu->networks[menu->count++];
  snprintf(network->ssid, sizeof(network->ssid), "%s", ssid);
  network->rssi = (int8_t)(rssi < -128 ? -128 : (rssi > 0 ? 0 : rssi));
  network->secured = secured;
  network->saved = saved;
  return true;
}

void wifi_menu_scan_done(wifi_menu_t *menu)
{
  menu->screen = MENU_LIST;
  menu->selected = 0;
  menu->scroll = 0;
}

const menu_network_t *wifi_menu_selected(const wifi_menu_t *menu)
{
  if (menu->count == 0 || menu->selected < 0 || menu->selected >= menu->count)
    return NULL;
  return &menu->networks[menu->selected];
}

static void move_selection(wifi_menu_t *menu, int delta)
{
  // Wraps around at both ends
  menu->selected = (menu->selected + delta + menu->count) % menu->count;
  if (menu->selected < menu->scroll)
    menu->scroll = menu->selected;
  else if (menu->selected >= menu->scroll + MENU_VISIBLE_ROWS)
    menu->scroll = menu->selected - MENU_VISIBLE_ROWS + 1;
}

static menu_action_t list_key(wifi_menu_t *menu, uint8_t key)
{
  switch (key)
  {
  case KC_UP:
  case ';': // the arrow keys work without fn here - there is no text to type
    if (menu->count == 0)
      return MENU_ACT_NONE;
    move_selection(menu, -1);
    return MENU_ACT_REDRAW;
  case KC_DOWN:
  case '.':
    if (menu->count == 0)
      return MENU_ACT_NONE;
    move_selection(menu, 1);
    return MENU_ACT_REDRAW;
  case 'r':
  case 'R':
    start_scan(menu);
    return MENU_ACT_SCAN;
  case KC_ENTER:
  {
    const menu_network_t *network = wifi_menu_selected(menu);
    if (!network)
      return MENU_ACT_NONE;
    if (network->secured && !network->saved)
    {
      menu->screen = MENU_PASSWORD;
      menu->password[0] = '\0';
      menu->password_len = 0;
      return MENU_ACT_REDRAW;
    }
    menu->password[0] = '\0';
    menu->password_len = 0;
    menu->password_entered = !network->secured; // open: no password; saved: keep the saved one
    menu->screen = MENU_CLOSED;
    return MENU_ACT_CONNECT;
  }
  case 'p':
  case 'P':
  {
    // Saved network with a changed password: type it anyway
    const menu_network_t *network = wifi_menu_selected(menu);
    if (!network || !network->secured)
      return MENU_ACT_NONE;
    menu->screen = MENU_PASSWORD;
    menu->password[0] = '\0';
    menu->password_len = 0;
    return MENU_ACT_REDRAW;
  }
  case KC_ESC:
  case KC_BACKSPACE:
  case '`':
    menu->screen = MENU_CLOSED;
    return MENU_ACT_CLOSE;
  default:
    return MENU_ACT_NONE;
  }
}

static menu_action_t password_key(wifi_menu_t *menu, uint8_t key)
{
  if (key == KC_ENTER)
  {
    if (menu->password_len < MENU_PASSWORD_MIN)
      return MENU_ACT_NONE; // too short for WPA2 - the screen says so
    menu->password_entered = true;
    menu->screen = MENU_CLOSED;
    return MENU_ACT_CONNECT;
  }
  if (key == KC_ESC)
  {
    menu->screen = MENU_LIST;
    return MENU_ACT_REDRAW;
  }
  if (key == KC_BACKSPACE)
  {
    if (menu->password_len == 0)
      return MENU_ACT_NONE;
    menu->password[--menu->password_len] = '\0';
    return MENU_ACT_REDRAW;
  }
  if (key >= 0x20 && key <= 0x7E)
  {
    if (menu->password_len >= MENU_PASSWORD_MAX)
      return MENU_ACT_NONE;
    menu->password[menu->password_len++] = (char)key;
    menu->password[menu->password_len] = '\0';
    return MENU_ACT_REDRAW;
  }
  return MENU_ACT_NONE;
}

menu_action_t wifi_menu_key(wifi_menu_t *menu, uint8_t key)
{
  switch (menu->screen)
  {
  case MENU_LIST:
    return list_key(menu, key);
  case MENU_PASSWORD:
    return password_key(menu, key);
  case MENU_SCANNING:
    if (key == KC_ESC || key == '`')
    {
      menu->screen = MENU_CLOSED;
      return MENU_ACT_CLOSE;
    }
    return MENU_ACT_NONE;
  default:
    return MENU_ACT_NONE;
  }
}
