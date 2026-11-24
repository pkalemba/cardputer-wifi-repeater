/*
 * Bluetooth trackers - see trackers.h
 */

#include "trackers.h"

#include <stdio.h>
#include <string.h>

/* BLE advertising data types */
#define AD_UUID16_INCOMPLETE 0x02
#define AD_UUID16_COMPLETE 0x03
#define AD_SERVICE_DATA16 0x16
#define AD_MANUFACTURER 0xFF

#define COMPANY_APPLE 0x004C
#define APPLE_TYPE_FINDMY 0x12
#define APPLE_FINDMY_LEN_SEPARATED 0x19 // whole public key: away from the owner

#define UUID_GOOGLE_FMDN 0xFEAA // Eddystone service, FMDN frame types 0x40 / 0x41
#define FMDN_FRAME 0x40
#define FMDN_FRAME_UTP 0x41 // unwanted tracking protection mode
#define UUID_SAMSUNG_SMARTTAG 0xFD5A
#define UUID_TILE 0xFEED
#define UUID_TILE_2 0xFEEC
#define UUID_CHIPOLO 0xFE33

static tracker_type_t type_of_uuid16(uint16_t uuid)
{
  switch (uuid)
  {
  case UUID_SAMSUNG_SMARTTAG:
    return TRACKER_SAMSUNG_SMARTTAG;
  case UUID_TILE:
  case UUID_TILE_2:
    return TRACKER_TILE;
  case UUID_CHIPOLO:
    return TRACKER_CHIPOLO;
  default:
    return TRACKER_NONE;
  }
}

bool tracker_parse_adv(const uint8_t *data, size_t len, tracker_adv_t *out)
{
  tracker_adv_t found = {TRACKER_NONE, SEPARATED_UNKNOWN};

  // AD structures: [length][type][length - 1 bytes]
  size_t pos = 0;
  while (pos + 1 < len && found.type == TRACKER_NONE)
  {
    size_t field_len = data[pos];
    if (field_len == 0 || pos + 1 + field_len > len)
      break;
    uint8_t ad_type = data[pos + 1];
    const uint8_t *value = data + pos + 2;
    size_t value_len = field_len - 1;

    if (ad_type == AD_MANUFACTURER && value_len >= 4 && (value[0] | value[1] << 8) == COMPANY_APPLE &&
        value[2] == APPLE_TYPE_FINDMY)
    {
      found.type = TRACKER_APPLE_FINDMY;
      found.separated = value[3] == APPLE_FINDMY_LEN_SEPARATED ? SEPARATED_YES : SEPARATED_NO;
    }
    else if (ad_type == AD_SERVICE_DATA16 && value_len >= 2)
    {
      uint16_t uuid = value[0] | value[1] << 8;
      if (uuid == UUID_GOOGLE_FMDN)
      {
        // Plain Eddystone beacons use frame types 0x00-0x30
        if (value_len >= 3 && (value[2] == FMDN_FRAME || value[2] == FMDN_FRAME_UTP))
        {
          found.type = TRACKER_GOOGLE_FMDN;
          found.separated = value[2] == FMDN_FRAME_UTP ? SEPARATED_YES : SEPARATED_UNKNOWN;
        }
      }
      else
      {
        found.type = type_of_uuid16(uuid);
      }
    }
    else if (ad_type == AD_UUID16_INCOMPLETE || ad_type == AD_UUID16_COMPLETE)
    {
      for (size_t i = 0; i + 1 < value_len && found.type == TRACKER_NONE; i += 2)
        found.type = type_of_uuid16(value[i] | value[i + 1] << 8);
    }
    pos += 1 + field_len;
  }

  if (found.type == TRACKER_NONE)
    return false;
  *out = found;
  return true;
}

const char *tracker_type_name(tracker_type_t type)
{
  switch (type)
  {
  case TRACKER_APPLE_FINDMY:
    return "AirTag/FindMy";
  case TRACKER_GOOGLE_FMDN:
    return "Google FMDN";
  case TRACKER_SAMSUNG_SMARTTAG:
    return "SmartTag";
  case TRACKER_TILE:
    return "Tile";
  case TRACKER_CHIPOLO:
    return "Chipolo";
  default:
    return "?";
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * Table
 * ═══════════════════════════════════════════════════════════════════ */

void tracker_table_init(tracker_table_t *table)
{
  memset(table, 0, sizeof(*table));
  table->follow_s = TRACKER_DEFAULT_FOLLOW_S;
}

tracker_level_t tracker_level(const tracker_entry_t *entry, uint32_t follow_s)
{
  // With its owner nearby a tracker belongs to someone around you
  if (entry->ignored || entry->separated == SEPARATED_NO)
    return LEVEL_NEARBY;

  uint32_t span = entry->last_seen - entry->first_seen;
  uint32_t span_minutes = span / 60 + 1;
  bool present = entry->minutes_seen * 100 >= span_minutes * TRACKER_PRESENCE_PERCENT;
  if (span >= follow_s && present)
    return LEVEL_ALERT;
  if (span >= follow_s / 3 && present)
    return LEVEL_WATCH;
  return LEVEL_NEARBY;
}

/* Slot for a new tracker: a free one, else the least important one (not an alert) */
static int free_slot(tracker_table_t *table)
{
  int victim = -1;
  for (int i = 0; i < TRACKER_TABLE_SIZE; i++)
  {
    const tracker_entry_t *e = &table->entries[i];
    if (!e->used)
      return i;
    if (e->level == LEVEL_ALERT)
      continue;
    if (victim < 0)
    {
      victim = i;
      continue;
    }
    const tracker_entry_t *v = &table->entries[victim];
    if (e->level < v->level || (e->level == v->level && e->last_seen < v->last_seen))
      victim = i;
  }
  return victim;
}

int tracker_table_update(tracker_table_t *table, const uint8_t addr[6], const tracker_adv_t *adv, int rssi,
                         uint32_t now_s, bool *new_alert)
{
  *new_alert = false;
  int index = -1;
  for (int i = 0; i < TRACKER_TABLE_SIZE; i++)
    if (table->entries[i].used && memcmp(table->entries[i].addr, addr, 6) == 0)
    {
      index = i;
      break;
    }

  if (index < 0)
  {
    index = free_slot(table);
    if (index < 0)
      return -1;
    tracker_entry_t *e = &table->entries[index];
    memset(e, 0, sizeof(*e));
    e->used = true;
    memcpy(e->addr, addr, 6);
    e->first_seen = now_s;
    e->last_minute = now_s / 60;
    e->minutes_seen = 1;
    e->rssi_max = -128;
  }

  tracker_entry_t *e = &table->entries[index];
  e->type = adv->type;
  // An AirTag sends the short form while its owner is around: remember "separated" only while it lasts
  if (adv->separated != SEPARATED_UNKNOWN || e->separated == SEPARATED_UNKNOWN)
    e->separated = adv->separated;
  if (now_s > e->last_seen)
    e->last_seen = now_s;
  if (now_s / 60 != e->last_minute)
  {
    e->last_minute = now_s / 60;
    e->minutes_seen++;
  }
  e->adv_count++;
  if (rssi < -128)
    rssi = -128;
  if (rssi > 0)
    rssi = 0;
  e->rssi = (int8_t)rssi;
  if (e->rssi > e->rssi_max)
    e->rssi_max = e->rssi;

  tracker_level_t level = tracker_level(e, table->follow_s);
  *new_alert = level == LEVEL_ALERT && e->level != LEVEL_ALERT;
  e->level = level;
  return index;
}

int tracker_table_tick(tracker_table_t *table, uint32_t now_s)
{
  int alerts = 0;
  for (int i = 0; i < TRACKER_TABLE_SIZE; i++)
  {
    tracker_entry_t *e = &table->entries[i];
    if (!e->used)
      continue;
    if (now_s - e->last_seen >= TRACKER_EXPIRE_S)
    {
      e->used = false;
      continue;
    }
    e->level = tracker_level(e, table->follow_s);
    if (e->level == LEVEL_ALERT)
      alerts++;
  }
  return alerts;
}

void tracker_set_ignored(tracker_table_t *table, int index, bool ignored)
{
  if (index < 0 || index >= TRACKER_TABLE_SIZE || !table->entries[index].used)
    return;
  tracker_entry_t *e = &table->entries[index];
  e->ignored = ignored;
  e->level = tracker_level(e, table->follow_s);
}

static bool sorts_before(const tracker_entry_t *a, const tracker_entry_t *b)
{
  if (a->ignored != b->ignored)
    return !a->ignored;
  if (a->level != b->level)
    return a->level > b->level;
  return a->rssi > b->rssi;
}

int tracker_table_sorted(const tracker_table_t *table, int *indexes, int max_count)
{
  int count = 0;
  for (int i = 0; i < TRACKER_TABLE_SIZE && count < max_count; i++)
  {
    if (!table->entries[i].used)
      continue;
    // Insertion sort - the table is small
    int pos = count++;
    while (pos > 0 && sorts_before(&table->entries[i], &table->entries[indexes[pos - 1]]))
    {
      indexes[pos] = indexes[pos - 1];
      pos--;
    }
    indexes[pos] = i;
  }
  return count;
}

void format_mac(char *out, size_t out_len, const uint8_t mac[6])
{
  snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_duration(char *out, size_t out_len, uint32_t seconds)
{
  if (seconds < 60)
    snprintf(out, out_len, "%us", (unsigned)seconds);
  else if (seconds < 3600)
    snprintf(out, out_len, "%um", (unsigned)(seconds / 60));
  else
    snprintf(out, out_len, "%uh%02u", (unsigned)(seconds / 3600), (unsigned)(seconds / 60 % 60));
}
