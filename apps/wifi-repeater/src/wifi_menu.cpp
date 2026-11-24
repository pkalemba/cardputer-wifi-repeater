/*
 * On-device WiFi menu - see wifi_menu.h
 */

#include "wifi_menu.h"

#include <stdio.h>
#include <string.h>

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
  // The arrow keys (; . , /) work without fn here - there is no text to type
  case KC_UP:
  case ';':
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
  case KC_RIGHT:
  case '/':
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
  case KC_LEFT:
  case ',':
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
  if (key == KC_ESC || key == KC_LEFT) // fn+` or fn+left (plain , is text here)
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
    if (key == KC_ESC || key == KC_LEFT || key == ',' || key == '`')
    {
      menu->screen = MENU_CLOSED;
      return MENU_ACT_CLOSE;
    }
    return MENU_ACT_NONE;
  default:
    return MENU_ACT_NONE;
  }
}
