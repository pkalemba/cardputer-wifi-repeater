/*
 * Room scanner for the M5Stack Cardputer - a quick check of a hotel room
 * or rental for hidden WiFi cameras.
 *
 * Listens to WiFi on channels 1-13 (promiscuous mode, nothing is sent)
 * and lists the devices it hears, most suspicious first: camera makers'
 * MAC addresses, camera-like network names, devices uploading a steady
 * stream of data, and a strong signal (close by). The detail view stays on
 * the device's channel and shows its signal, so it can be found by
 * walking around the room. See roomscan.h for what it can and cannot find.
 *
 * Keys (Cardputer ADV): arrows (fn + ; . , /) select, Enter shows the
 * detail view, Esc goes back, A shows all devices / only suspicious ones,
 * C clears the list, ? shows the help.
 * G0 (every Cardputer): short press - next device, hold 1 s - detail view.
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "cardputer_battery.h"
#include "cardputer_display.h"
#include "cardputer_input.h"
#include "firmware_version.h"
#include "roomscan.h"

static const char *TAG = "roomscan";

#define CHANNEL_FIRST 1
#define CHANNEL_LAST 13       // 14 is only used in Japan (802.11b)
#define CHANNEL_DWELL_MS 300  // per channel while hopping
#define FRAME_QUEUE_LEN 64
#define SCREEN_TIMEOUT_S 120
#define LIST_TOP 22
#define LIST_ROW_H 13
#define LIST_ROWS 7
#define G0_LONG_PRESS_MS 1000

typedef struct
{
  wifi_frame_t frame;
  uint8_t channel;
  int8_t rssi;
} frame_event_t;

static room_scan_t scan;
static SemaphoreHandle_t scan_mutex;
static QueueHandle_t frame_queue;
static volatile uint8_t current_channel = CHANNEL_FIRST;
static volatile uint8_t locked_channel = 0; // 0 = hopping
static uint32_t dropped_frames = 0;
static bool wifi_ok = false;

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }
static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

/* ═══════════════════════════════════════════════════════════════════
 * WIFI LISTENING (promiscuous mode)
 * ═══════════════════════════════════════════════════════════════════ */

/* Runs in the WiFi task: parse and queue, nothing more */
static void promiscuous_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)
    return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  int len = pkt->rx_ctrl.sig_len - 4; // without the FCS
  if (len <= 0)
    return;

  frame_event_t event;
  if (!wifi_parse_frame(pkt->payload, (size_t)len, &event.frame))
    return;
  event.channel = current_channel;
  event.rssi = pkt->rx_ctrl.rssi;
  if (xQueueSend(frame_queue, &event, 0) != pdTRUE)
    dropped_frames = dropped_frames + 1;
}

static bool wifi_listen_init(void)
{
  esp_err_t err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    return false;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&cfg) != ESP_OK)
    return false;
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL); // listen only, no network
  if (esp_wifi_start() != ESP_OK)
    return false;

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(promiscuous_rx);
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  return esp_wifi_set_promiscuous(true) == ESP_OK;
}

/* Feeds the queued frames into the device table and hops channels */
static void scan_task(void *param)
{
  uint32_t channel_since = now_ms();
  while (1)
  {
    frame_event_t event;
    if (xQueueReceive(frame_queue, &event, pdMS_TO_TICKS(20)) == pdTRUE)
    {
      xSemaphoreTake(scan_mutex, portMAX_DELAY);
      room_scan_frame(&scan, &event.frame, event.channel, event.rssi, now_s());
      xSemaphoreGive(scan_mutex);
    }

    uint32_t now = now_ms();
    if (now - channel_since < CHANNEL_DWELL_MS)
      continue;

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    room_scan_dwell(&scan, current_channel, now - channel_since);
    xSemaphoreGive(scan_mutex);
    channel_since = now;

    uint8_t next = locked_channel;
    if (next == 0)
      next = current_channel >= CHANNEL_LAST ? CHANNEL_FIRST : current_channel + 1;
    if (next != current_channel)
    {
      // Frames still queued were heard on the old channel - they keep it in their event
      current_channel = next;
      esp_wifi_set_channel(next, WIFI_SECOND_CHAN_NONE);
    }
  }
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
static bool show_all = false;   // all devices, not only suspicious ones
static int selected = 0;        // position in the sorted list
static int selected_entry = -1; // its table index
static int scroll = 0;
static uint32_t scan_started = 0;

static uint16_t risk_color(risk_t risk)
{
  switch (risk)
  {
  case RISK_HIGH:
    return THEME_ERROR;
  case RISK_MEDIUM:
    return THEME_WARNING;
  case RISK_LOW:
    return THEME_CHECKING;
  default:
    return THEME_BORDER;
  }
}

/* Name for the list: the network of an access point, else the maker, else the address */
static void device_label(char *out, size_t out_len, const room_device_t *d)
{
  if (d->is_ap && d->ssid[0])
    snprintf(out, out_len, "%s", d->ssid);
  else if (d->vendor)
    snprintf(out, out_len, "%s", d->vendor->name);
  else
    snprintf(out, out_len, "%02X%02X%02X%s", d->mac[3], d->mac[4], d->mac[5], mac_is_random(d->mac) ? " rnd" : "");
}

static void draw_title(int high)
{
  uint16_t bar = high > 0 ? GRUV_RED : THEME_BAR;
  uint16_t text = high > 0 ? GRUV_BG0 : THEME_TITLE;
  lcd_fill_rect(0, 0, LCD_V_RES, 18, bar);
  if (high > 0)
  {
    char title[32];
    snprintf(title, sizeof(title), "%d SUSPICIOUS", high);
    lcd_draw_string(5, 5, title, text, bar);
  }
  else
  {
    lcd_draw_string(5, 5, "ROOM SCAN", text, bar);
  }
  ui_draw_battery(236, 4, bar);
}

static void draw_hint(const char *hint)
{
  lcd_fill_rect(0, LCD_H_RES - 12, LCD_V_RES, 12, THEME_BAR);
  lcd_draw_string(4, LCD_H_RES - 10, hint, THEME_DIM, THEME_BAR);
}

static void draw_list(const int *order, int count, int high, int total)
{
  lcd_fill_screen(THEME_BG);
  draw_title(high);

  if (!wifi_ok)
  {
    lcd_draw_string(8, 50, "WiFi failed", THEME_ERROR, THEME_BG);
    return;
  }

  char line[48];
  if (count == 0)
  {
    lcd_draw_string(8, 30, show_all ? "Nothing heard yet" : "Nothing suspicious", THEME_TEXT, THEME_BG);
    snprintf(line, sizeof(line), "%d devices, ch %d", total, current_channel);
    lcd_draw_string(8, 48, line, THEME_DIM, THEME_BG);
    uint32_t elapsed = now_s() - scan_started;
    snprintf(line, sizeof(line), "Listening %lus", (unsigned long)elapsed);
    lcd_draw_string(8, 61, line, THEME_DIM, THEME_BG);
    lcd_draw_string(8, 80, "Give it a minute and", THEME_DIM, THEME_BG);
    lcd_draw_string(8, 93, "walk around the room", THEME_DIM, THEME_BG);
    draw_hint("A:all devices ?:help");
    return;
  }

  for (int row = 0; row < LIST_ROWS && scroll + row < count; row++)
  {
    const room_device_t *d = &scan.devices[order[scroll + row]];
    int y = LIST_TOP + row * LIST_ROW_H;
    bool is_selected = scroll + row == selected;
    uint16_t bg = is_selected ? THEME_BAR : THEME_BG;
    lcd_fill_rect(0, y - 2, LCD_V_RES, LIST_ROW_H, bg);
    lcd_fill_rect(3, y, 6, 8, risk_color(d->risk));

    char label[33];
    device_label(label, sizeof(label), d);
    label[14] = '\0';
    lcd_draw_string(14, y, label, THEME_TEXT, bg);
    lcd_draw_string(134, y, d->is_ap ? "AP" : "  ", THEME_DIM, bg);
    snprintf(line, sizeof(line), "%4d", d->rssi);
    lcd_draw_string(170, y, line, THEME_DIM, bg);
    ui_draw_signal_bars(206, y, d->rssi);
  }

  snprintf(line, sizeof(line), "%d/%d ch%d", selected + 1, count, current_channel);
  lcd_draw_string(LCD_V_RES - 4 - (int)strlen(line) * FONT_W, LIST_TOP + LIST_ROWS * LIST_ROW_H, line, THEME_DIM,
                  THEME_BG);
  draw_hint(show_all ? "Enter:find A:suspicious ?" : "Enter:find A:all ?:help");
}

static void draw_detail(int high)
{
  lcd_fill_screen(THEME_BG);
  draw_title(high);
  if (selected_entry < 0 || !scan.devices[selected_entry].used)
  {
    lcd_draw_string(8, 50, "Device gone", THEME_DIM, THEME_BG);
    draw_hint("Esc: back");
    return;
  }

  const room_device_t *d = &scan.devices[selected_entry];
  char line[64], reasons[48];

  lcd_fill_rect(4, 23, 6, 8, risk_color(d->risk));
  snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X%s", d->mac[0], d->mac[1], d->mac[2], d->mac[3],
           d->mac[4], d->mac[5], mac_is_random(d->mac) ? " rnd" : "");
  lcd_draw_string(16, 23, line, THEME_TEXT, THEME_BG);

  snprintf(line, sizeof(line), "%s %s", d->is_ap ? "AP" : "Device", d->vendor ? d->vendor->name : "(unknown maker)");
  lcd_draw_string(4, 35, line, THEME_DIM, THEME_BG);
  if (d->ssid[0])
  {
    snprintf(line, sizeof(line), "%s%s", d->is_ap ? "Net: " : "On: ", d->ssid);
    line[29] = '\0';
    lcd_draw_string(4, 47, line, THEME_TEXT, THEME_BG);
  }
  snprintf(line, sizeof(line), "Ch %d  upload %lu.%lu KB/s", d->channel, (unsigned long)(d->upload_rate / 1000),
           (unsigned long)(d->upload_rate % 1000 / 100));
  lcd_draw_string(4, 59, line, THEME_DIM, THEME_BG);

  room_reasons_text(reasons, sizeof(reasons), d->reasons);
  lcd_draw_string(4, 71, reasons[0] ? reasons : "no reason to worry", d->risk >= RISK_MEDIUM ? THEME_WARNING : THEME_DIM,
                  THEME_BG);

  // Signal: walk around, the bar grows near the device
  bool fresh = now_s() - d->last_seen < 5;
  snprintf(line, sizeof(line), "%d dBm (max %d)", d->rssi, d->rssi_max);
  lcd_draw_string(4, 87, line, fresh ? THEME_TEXT : THEME_DIM, THEME_BG);
  ui_draw_rssi_meter(4, 99, 232, 14, fresh ? d->rssi : -100, THEME_OK);

  snprintf(line, sizeof(line), "Esc:back  on ch %d", d->channel);
  draw_hint(line);
}

static void draw_help(void)
{
  static const char *const lines[] = {
      "Fn+; Fn+.  select",
      "Enter      find (signal)",
      "Esc        back",
      "A          all / suspicious",
      "C          clear list",
      "G0         next / hold: find",
      "Hints only: no camera on",
      "WiFi 2.4GHz = not found",
  };
  lcd_fill_screen(THEME_BG);
  lcd_fill_rect(0, 0, LCD_V_RES, 18, THEME_BAR);
  lcd_draw_string(5, 5, "HELP " FIRMWARE_VERSION, THEME_TITLE, THEME_BAR);
  for (int i = 0; i < (int)(sizeof(lines) / sizeof(lines[0])); i++)
    lcd_draw_string(4, 24 + i * 13, lines[i], i < 6 ? THEME_TEXT : THEME_DIM, THEME_BG);
}

static void redraw(void)
{
  int order[ROOM_MAX_DEVICES];
  xSemaphoreTake(scan_mutex, portMAX_DELAY);
  int high = room_scan_tick(&scan, now_s());
  int total = room_scan_sorted(&scan, RISK_NONE, order, ROOM_MAX_DEVICES);
  int count = room_scan_sorted(&scan, show_all ? RISK_NONE : RISK_LOW, order, ROOM_MAX_DEVICES);

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
    draw_detail(high);
  else
    draw_list(order, count, high, total);
  lcd_flush();
  display_unlock();
  xSemaphoreGive(scan_mutex);
}

static void move_selection(int delta)
{
  int order[ROOM_MAX_DEVICES];
  xSemaphoreTake(scan_mutex, portMAX_DELAY);
  int count = room_scan_sorted(&scan, show_all ? RISK_NONE : RISK_LOW, order, ROOM_MAX_DEVICES);
  if (count > 0)
  {
    selected = (selected + delta + count) % count;
    selected_entry = order[selected];
  }
  xSemaphoreGive(scan_mutex);
}

static void set_screen(screen_t next)
{
  screen = next;
  // The detail view stays on the device's channel: steady signal readings
  uint8_t lock = 0;
  if (screen == SCREEN_DETAIL && selected_entry >= 0)
  {
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    lock = scan.devices[selected_entry].channel;
    xSemaphoreGive(scan_mutex);
  }
  locked_channel = lock;
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
      set_screen(SCREEN_DETAIL);
    break;
  case KC_ESC:
  case KC_BACKSPACE:
    set_screen(SCREEN_LIST);
    break;
  case 'a':
  case 'A':
    show_all = !show_all;
    selected = 0;
    selected_entry = -1;
    scroll = 0;
    break;
  case 'c':
  case 'C':
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    room_scan_init(&scan);
    xSemaphoreGive(scan_mutex);
    scan_started = now_s();
    selected = 0;
    selected_entry = -1;
    scroll = 0;
    set_screen(SCREEN_LIST);
    break;
  case '?':
  case '/':
    set_screen(screen == SCREEN_HELP ? SCREEN_LIST : SCREEN_HELP);
    break;
  default:
    break;
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * UI TASK: keys, G0, screen timeout
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
    bool activity = false;

    // G0: short press - next device (or back), hold - detail view
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
      activity = true;
    }
    else if (!pressed && was_pressed && !long_press_done)
    {
      if (display_on)
        handle_key(screen == SCREEN_LIST ? KC_DOWN : KC_ESC);
      activity = true;
    }
    was_pressed = pressed;

    uint8_t keys[8];
    int key_count = keyboard_read_keys(keys, sizeof(keys));
    for (int i = 0; i < key_count; i++)
    {
      if (display_on) // the first key only wakes the screen
        handle_key(keys[i]);
      activity = true;
    }

    if (activity)
    {
      last_activity = now;
      if (!display_on)
      {
        display_on = true;
        redraw();
        lcd_backlight(true);
      }
    }

    if (display_on && (activity || now - last_redraw >= pdMS_TO_TICKS(500)))
    {
      redraw();
      last_redraw = now;
    }

    if (display_on && screen != SCREEN_DETAIL && now - last_activity >= pdMS_TO_TICKS(SCREEN_TIMEOUT_S * 1000))
    {
      display_on = false;
      lcd_backlight(false);
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
  ESP_LOGI(TAG, "Room scanner %s", FIRMWARE_VERSION);

  esp_err_t ret = nvs_flash_init(); // WiFi keeps its calibration data here
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  scan_mutex = xSemaphoreCreateMutex();
  frame_queue = xQueueCreate(FRAME_QUEUE_LEN, sizeof(frame_event_t));
  room_scan_init(&scan);

  battery_init();
  battery_sample();
  button_g0_init();
  keyboard_init();

  if (lcd_init())
  {
    lcd_fill_screen(THEME_BG);
    lcd_fill_rect(0, 0, LCD_V_RES, 18, THEME_BAR);
    lcd_draw_string(5, 5, "ROOM SCAN", THEME_TITLE, THEME_BAR);
    lcd_draw_string(8, 50, "Starting WiFi...", THEME_TEXT, THEME_BG);
    lcd_flush();
    lcd_backlight(true);
  }

  wifi_ok = wifi_listen_init();
  if (!wifi_ok)
    ESP_LOGE(TAG, "WiFi listening failed");
  scan_started = now_s();
  xTaskCreate(scan_task, "scan", 4096, NULL, 6, NULL);
  xTaskCreate(ui_task, "ui", 4096, NULL, 5, NULL);
}
