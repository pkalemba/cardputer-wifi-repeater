/*
 * Tracker detector for the M5Stack Cardputer
 *
 * Listens for Bluetooth trackers (AirTag and other Find My accessories,
 * Google Find My Device trackers, Samsung SmartTag, Tile, Chipolo) and
 * warns when one seems to travel with you: away from its owner and around
 * you for 10 minutes or more. The detail view shows the signal strength,
 * so the tracker can be found by walking around with the Cardputer.
 *
 * Keys (Cardputer ADV): arrows (fn + ; . , /) select, Enter shows the
 * detail view, Esc goes back, I ignores the tracker (yours or a
 * companion's), C clears the list, ? shows the help.
 * G0 (every Cardputer): short press - next tracker, hold 1 s - detail view.
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "cardputer_battery.h"
#include "cardputer_display.h"
#include "cardputer_input.h"
#include "firmware_version.h"
#include "trackers.h"

static const char *TAG = "trackers";

#define SCREEN_TIMEOUT_S 60
#define LIST_TOP 22
#define LIST_ROW_H 13
#define LIST_ROWS 7
#define G0_LONG_PRESS_MS 1000

/* Tracker table, shared by the BLE host task and the UI task */
static tracker_table_t table;
static SemaphoreHandle_t table_mutex;
static uint32_t adv_seen = 0;                  // all advertisements (scanner is alive)
static volatile bool alert_pending = false; // a tracker just reached LEVEL_ALERT

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

/* ═══════════════════════════════════════════════════════════════════
 * BLE SCANNING (NimBLE, passive)
 * ═══════════════════════════════════════════════════════════════════ */

static void start_scan(void);

static int gap_event(struct ble_gap_event *event, void *arg)
{
  switch (event->type)
  {
  case BLE_GAP_EVENT_DISC:
  {
    adv_seen = adv_seen + 1;
    tracker_adv_t adv;
    if (!tracker_parse_adv(event->disc.data, event->disc.length_data, &adv))
      return 0;
    // NimBLE keeps addresses least significant byte first
    uint8_t addr[6];
    for (int i = 0; i < 6; i++)
      addr[i] = event->disc.addr.val[5 - i];
    bool new_alert = false;
    xSemaphoreTake(table_mutex, portMAX_DELAY);
    tracker_table_update(&table, addr, &adv, event->disc.rssi, now_s(), &new_alert);
    xSemaphoreGive(table_mutex);
    if (new_alert)
    {
      ESP_LOGW(TAG, "%s %02X:%02X:%02X:%02X:%02X:%02X seems to travel with you", tracker_type_name(adv.type),
               addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
      alert_pending = true;
    }
    return 0;
  }
  case BLE_GAP_EVENT_DISC_COMPLETE:
    start_scan();
    return 0;
  default:
    return 0;
  }
}

static void start_scan(void)
{
  uint8_t own_addr_type;
  if (ble_hs_id_infer_auto(0, &own_addr_type) != 0)
  {
    ESP_LOGE(TAG, "No Bluetooth address");
    return;
  }
  struct ble_gap_disc_params params;
  memset(&params, 0, sizeof(params));
  params.passive = 1;           // only listen, never ask for scan responses
  params.filter_duplicates = 0; // every advertisement counts (presence over time)
  params.itvl = 0x50;           // 50 ms window every 50 ms: scan all the time
  params.window = 0x50;
  int rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &params, gap_event, NULL);
  if (rc != 0)
    ESP_LOGE(TAG, "Scan failed to start: %d", rc);
}

static void on_sync(void) { start_scan(); }

static void on_reset(int reason) { ESP_LOGW(TAG, "Bluetooth reset (%d)", reason); }

static void host_task(void *param)
{
  nimble_port_run(); // returns when nimble_port_stop() is called
  nimble_port_freertos_deinit();
}

static bool bluetooth_init(void)
{
  if (nimble_port_init() != ESP_OK)
  {
    ESP_LOGE(TAG, "Bluetooth init failed");
    return false;
  }
  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;
  nimble_port_freertos_init(host_task);
  return true;
}

/* ═══════════════════════════════════════════════════════════════════
 * SCREENS
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum
{
  SCREEN_LIST,
  SCREEN_DETAIL,
  SCREEN_HELP,
} screen_t;

static screen_t screen = SCREEN_LIST;
static int selected = 0;        // position in the sorted list
static int selected_entry = -1; // its table index (detail view follows it)
static int scroll = 0;
static bool bluetooth_ok = false;

static uint16_t level_color(const tracker_entry_t *e)
{
  if (e->ignored)
    return THEME_BORDER;
  switch (e->level)
  {
  case LEVEL_ALERT:
    return THEME_ERROR;
  case LEVEL_WATCH:
    return THEME_WARNING;
  default:
    return THEME_DIM;
  }
}

static void draw_title(int alerts)
{
  uint16_t bar = alerts > 0 ? GRUV_RED : THEME_BAR;
  uint16_t text = alerts > 0 ? GRUV_BG0 : THEME_TITLE;
  lcd_fill_rect(0, 0, LCD_V_RES, 18, bar);
  if (alerts > 0)
  {
    char title[32];
    snprintf(title, sizeof(title), "%d FOLLOWING YOU", alerts);
    lcd_draw_string(5, 5, title, text, bar);
  }
  else
  {
    lcd_draw_string(5, 5, "TRACKERS", text, bar);
  }
  ui_draw_battery(236, 4, bar);
}

static void draw_hint(const char *hint)
{
  lcd_fill_rect(0, LCD_H_RES - 12, LCD_V_RES, 12, THEME_BAR);
  lcd_draw_string(4, LCD_H_RES - 10, hint, THEME_DIM, THEME_BAR);
}

static void draw_list(const int *order, int count, int alerts)
{
  lcd_fill_screen(THEME_BG);
  draw_title(alerts);

  if (!bluetooth_ok)
  {
    lcd_draw_string(8, 50, "Bluetooth failed", THEME_ERROR, THEME_BG);
    return;
  }
  if (count == 0)
  {
    lcd_draw_string(8, 42, "No trackers nearby", THEME_TEXT, THEME_BG);
    char line[32];
    snprintf(line, sizeof(line), "Listening... %lu adv", (unsigned long)adv_seen);
    lcd_draw_string(8, 62, line, THEME_DIM, THEME_BG);
    lcd_draw_string(8, 82, "Alert after 10 min", THEME_DIM, THEME_BG);
    lcd_draw_string(8, 95, "around you", THEME_DIM, THEME_BG);
    draw_hint("?: help");
    return;
  }

  uint32_t now = now_s();
  for (int row = 0; row < LIST_ROWS && scroll + row < count; row++)
  {
    const tracker_entry_t *e = &table.entries[order[scroll + row]];
    int y = LIST_TOP + row * LIST_ROW_H;
    bool is_selected = scroll + row == selected;
    uint16_t bg = is_selected ? THEME_BAR : THEME_BG;
    lcd_fill_rect(0, y - 2, LCD_V_RES, LIST_ROW_H, bg);
    lcd_fill_rect(3, y, 6, 8, level_color(e));

    char name[16];
    snprintf(name, sizeof(name), "%-13s", tracker_type_name(e->type));
    lcd_draw_string(14, y, name, e->ignored ? THEME_DIM : THEME_TEXT, bg);

    // Time around you, then the signal
    char span[8];
    format_duration(span, sizeof(span), now - e->first_seen);
    lcd_draw_string(126, y, span, THEME_DIM, bg);
    char rssi[12];
    snprintf(rssi, sizeof(rssi), "%4d", e->rssi);
    lcd_draw_string(170, y, rssi, THEME_DIM, bg);
    ui_draw_signal_bars(206, y, e->rssi);
  }
  if (count > LIST_ROWS)
  {
    char more[24];
    snprintf(more, sizeof(more), "%d/%d", selected + 1, count);
    lcd_draw_string(LCD_V_RES - 4 - (int)strlen(more) * FONT_W, LIST_TOP + LIST_ROWS * LIST_ROW_H, more,
                    THEME_DIM, THEME_BG);
  }
  draw_hint(CHAR_UP CHAR_DOWN " Enter:find I:ignore ?");
}

static const char *separated_text(tracker_separated_t separated)
{
  switch (separated)
  {
  case SEPARATED_YES:
    return "away from owner";
  case SEPARATED_NO:
    return "owner nearby";
  default:
    return "owner unknown";
  }
}

static void draw_detail(int alerts)
{
  lcd_fill_screen(THEME_BG);
  draw_title(alerts);
  if (selected_entry < 0 || !table.entries[selected_entry].used)
  {
    lcd_draw_string(8, 50, "Tracker gone", THEME_DIM, THEME_BG);
    draw_hint("Esc: back");
    return;
  }

  const tracker_entry_t *e = &table.entries[selected_entry];
  uint32_t now = now_s();
  char line[64], value[16];

  lcd_fill_rect(4, 24, 6, 8, level_color(e));
  lcd_draw_string(16, 24, tracker_type_name(e->type), THEME_TEXT, THEME_BG);
  format_mac(line, sizeof(line), e->addr);
  lcd_draw_string(16, 36, line, THEME_DIM, THEME_BG);
  lcd_draw_string(16, 48, e->ignored ? "ignored" : separated_text(e->separated),
                  e->separated == SEPARATED_YES && !e->ignored ? THEME_WARNING : THEME_DIM, THEME_BG);

  format_duration(value, sizeof(value), e->last_seen - e->first_seen);
  snprintf(line, sizeof(line), "With you %s, %u min", value, e->minutes_seen);
  lcd_draw_string(4, 64, line, THEME_TEXT, THEME_BG);
  format_duration(value, sizeof(value), now - e->last_seen);
  snprintf(line, sizeof(line), "Last seen %s ago", value);
  lcd_draw_string(4, 76, line, THEME_DIM, THEME_BG);

  // Signal: walk around, the bar grows near the tracker
  bool fresh = now - e->last_seen < 10;
  snprintf(line, sizeof(line), "%d dBm (max %d)", e->rssi, e->rssi_max);
  lcd_draw_string(4, 92, line, fresh ? THEME_TEXT : THEME_DIM, THEME_BG);
  ui_draw_rssi_meter(4, 104, 232, 14, fresh ? e->rssi : -100, THEME_OK);
  draw_hint(e->ignored ? "Esc:back I:unignore" : "Esc:back I:ignore");
}

static void draw_help(void)
{
  static const char *const lines[] = {
      "Fn+; Fn+.  select",
      "Enter      find (signal)",
      "Esc        back",
      "I          ignore tracker",
      "C          clear list",
      "G0         next / hold: find",
      "Red: away from its owner",
      "and with you for 10 min",
  };
  lcd_fill_screen(THEME_BG);
  lcd_fill_rect(0, 0, LCD_V_RES, 18, THEME_BAR);
  lcd_draw_string(5, 5, "HELP " FIRMWARE_VERSION, THEME_TITLE, THEME_BAR);
  for (int i = 0; i < (int)(sizeof(lines) / sizeof(lines[0])); i++)
    lcd_draw_string(4, 24 + i * 13, lines[i], i < 6 ? THEME_TEXT : THEME_DIM, THEME_BG);
}

/* Redraw from the current table; keeps the selection on the same tracker */
static void redraw(void)
{
  int order[TRACKER_TABLE_SIZE];
  xSemaphoreTake(table_mutex, portMAX_DELAY);
  int alerts = tracker_table_tick(&table, now_s());
  int count = tracker_table_sorted(&table, order, TRACKER_TABLE_SIZE);

  if (selected_entry >= 0)
    for (int i = 0; i < count; i++)
      if (order[i] == selected_entry)
        selected = i;
  if (selected >= count)
    selected = count > 0 ? count - 1 : 0;
  if (screen == SCREEN_LIST)
    selected_entry = count > 0 ? order[selected] : -1;
  if (selected < scroll)
    scroll = selected;
  if (selected >= scroll + LIST_ROWS)
    scroll = selected - LIST_ROWS + 1;

  display_lock();
  if (screen == SCREEN_HELP)
    draw_help();
  else if (screen == SCREEN_DETAIL)
    draw_detail(alerts);
  else
    draw_list(order, count, alerts);
  lcd_flush();
  display_unlock();
  xSemaphoreGive(table_mutex);
}

/* Move the selection in the sorted list (wraps around) */
static void move_selection(int delta)
{
  int order[TRACKER_TABLE_SIZE];
  xSemaphoreTake(table_mutex, portMAX_DELAY);
  int count = tracker_table_sorted(&table, order, TRACKER_TABLE_SIZE);
  if (count > 0)
  {
    selected = (selected + delta + count) % count;
    selected_entry = order[selected];
  }
  xSemaphoreGive(table_mutex);
}

static void handle_key(uint8_t key)
{
  switch (key)
  {
  case KC_UP:
    if (screen == SCREEN_LIST)
      move_selection(-1);
    break;
  case KC_DOWN:
    if (screen == SCREEN_LIST)
      move_selection(1);
    break;
  case KC_ENTER:
    if (screen == SCREEN_LIST && selected_entry >= 0)
      screen = SCREEN_DETAIL;
    break;
  case KC_ESC:
  case KC_BACKSPACE:
    screen = SCREEN_LIST;
    break;
  case 'i':
  case 'I':
    if (selected_entry >= 0 && screen != SCREEN_HELP)
    {
      xSemaphoreTake(table_mutex, portMAX_DELAY);
      tracker_set_ignored(&table, selected_entry, !table.entries[selected_entry].ignored);
      xSemaphoreGive(table_mutex);
    }
    break;
  case 'c':
  case 'C':
    xSemaphoreTake(table_mutex, portMAX_DELAY);
    tracker_table_init(&table);
    xSemaphoreGive(table_mutex);
    screen = SCREEN_LIST;
    selected = 0;
    selected_entry = -1;
    scroll = 0;
    break;
  case '?':
  case '/':
    screen = screen == SCREEN_HELP ? SCREEN_LIST : SCREEN_HELP;
    break;
  default:
    break;
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * UI TASK: keys, G0, screen timeout, alerts
 * ═══════════════════════════════════════════════════════════════════ */

static void ui_task(void *param)
{
  bool display_on = true;
  TickType_t last_activity = xTaskGetTickCount();
  TickType_t last_redraw = 0;
  TickType_t last_battery = xTaskGetTickCount();
  TickType_t pressed_since = 0;
  bool was_pressed = false;
  bool long_press_done = false;

  while (1)
  {
    TickType_t now = xTaskGetTickCount();
    bool changed = false;
    bool activity = false;

    // G0: short press - next tracker (or back), hold - detail view
    bool pressed = button_g0_pressed();
    if (pressed && !was_pressed)
    {
      pressed_since = now;
      long_press_done = false;
    }
    else if (pressed && !long_press_done && (now - pressed_since) * portTICK_PERIOD_MS >= G0_LONG_PRESS_MS)
    {
      long_press_done = true;
      if (display_on)
        handle_key(screen == SCREEN_LIST ? KC_ENTER : KC_ESC);
      activity = changed = true;
    }
    else if (!pressed && was_pressed && !long_press_done)
    {
      if (display_on)
      {
        if (screen == SCREEN_LIST)
          handle_key(KC_DOWN);
        else
          handle_key(KC_ESC);
      }
      activity = changed = true;
    }
    was_pressed = pressed;

    uint8_t keys[8];
    int key_count = keyboard_read_keys(keys, sizeof(keys));
    for (int i = 0; i < key_count; i++)
    {
      if (display_on) // the first key only wakes the screen
        handle_key(keys[i]);
      activity = changed = true;
    }

    if (alert_pending)
    {
      alert_pending = false;
      activity = changed = true;
    }

    if (activity)
    {
      last_activity = now;
      if (!display_on)
      {
        display_on = true;
        redraw(); // draw before the backlight comes on
        lcd_backlight(true);
      }
    }

    if (display_on && (changed || now - last_redraw >= pdMS_TO_TICKS(1000)))
    {
      redraw();
      last_redraw = now;
    }

    // Screen off without activity - except in the detail view (finding a tracker)
    if (display_on && screen != SCREEN_DETAIL && now - last_activity >= pdMS_TO_TICKS(SCREEN_TIMEOUT_S * 1000))
    {
      display_on = false;
      lcd_backlight(false);
    }
    if (!display_on)
    {
      // Keep the table tidy while the screen is off
      xSemaphoreTake(table_mutex, portMAX_DELAY);
      tracker_table_tick(&table, now_s());
      xSemaphoreGive(table_mutex);
    }

    if (now - last_battery >= pdMS_TO_TICKS(10000))
    {
      battery_sample();
      last_battery = now;
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

extern "C" void app_main(void)
{
  ESP_LOGI(TAG, "Tracker detector %s", FIRMWARE_VERSION);

  esp_err_t ret = nvs_flash_init(); // Bluetooth keeps its calibration data here
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  table_mutex = xSemaphoreCreateMutex();
  tracker_table_init(&table);

  battery_init();
  battery_sample();
  button_g0_init();
  keyboard_init();

  if (lcd_init())
  {
    lcd_fill_screen(THEME_BG);
    lcd_fill_rect(0, 0, LCD_V_RES, 18, THEME_BAR);
    lcd_draw_string(5, 5, "TRACKERS", THEME_TITLE, THEME_BAR);
    lcd_draw_string(8, 50, "Starting Bluetooth...", THEME_TEXT, THEME_BG);
    lcd_flush();
    lcd_backlight(true);
  }

  bluetooth_ok = bluetooth_init();
  xTaskCreate(ui_task, "ui", 4096, NULL, 5, NULL);
}
