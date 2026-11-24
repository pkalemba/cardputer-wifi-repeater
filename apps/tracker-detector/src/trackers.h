/*
 * Bluetooth trackers: recognizing their advertisements and deciding which
 * one seems to travel with you. No ESP-IDF dependencies - unit tested on
 * the host (test/host).
 *
 * Recognized (from the advertising data):
 *  - Apple Find My (AirTag and Find My accessories): manufacturer data of
 *    Apple (0x004C) with type 0x12. The long form (length 0x19, the whole
 *    public key) is sent while the tracker is away from its owner.
 *  - Google Find My Device network (FMDN, Android trackers): service data
 *    0xFEAA with frame type 0x40, or 0x41 in "unwanted tracking
 *    protection" mode (away from its owner).
 *  - Samsung SmartTag: service 0xFD5A
 *  - Tile: services 0xFEED / 0xFEEC
 *  - Chipolo: service 0xFE33
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
  TRACKER_NONE = 0,
  TRACKER_APPLE_FINDMY,
  TRACKER_GOOGLE_FMDN,
  TRACKER_SAMSUNG_SMARTTAG,
  TRACKER_TILE,
  TRACKER_CHIPOLO,
} tracker_type_t;

typedef enum
{
  SEPARATED_UNKNOWN = 0, // the advertisement does not tell
  SEPARATED_NO,          // its owner is nearby
  SEPARATED_YES,         // away from its owner
} tracker_separated_t;

typedef struct
{
  tracker_type_t type;
  tracker_separated_t separated;
} tracker_adv_t;

/* Tracker type and owner state from BLE advertising data; false if not a tracker */
bool tracker_parse_adv(const uint8_t *data, size_t len, tracker_adv_t *out);

/* Short name for the display, e.g. "AirTag/FindMy" */
const char *tracker_type_name(tracker_type_t type);

/* ═══════════════════════════════════════════════════════════════════
 * Trackers seen around you
 * ═══════════════════════════════════════════════════════════════════ */

#define TRACKER_TABLE_SIZE 40
#define TRACKER_EXPIRE_S (30 * 60)       // forgotten after this long without an advertisement
#define TRACKER_DEFAULT_FOLLOW_S (10 * 60) // around you this long: alert
#define TRACKER_PRESENCE_PERCENT 50      // ... and seen in at least this share of the minutes

typedef enum
{
  LEVEL_NEARBY = 0, // just seen
  LEVEL_WATCH,      // around for a third of the follow time
  LEVEL_ALERT,      // seems to travel with you
} tracker_level_t;

typedef struct
{
  bool used;
  bool ignored; // the user knows it (own or a companion's)
  tracker_type_t type;
  tracker_separated_t separated;
  uint8_t addr[6]; // BLE address (most significant byte first)
  uint32_t first_seen; // seconds
  uint32_t last_seen;
  uint32_t last_minute; // minute (last_seen / 60) last counted in minutes_seen
  uint16_t minutes_seen;
  uint32_t adv_count;
  int8_t rssi;     // last
  int8_t rssi_max; // strongest so far
  tracker_level_t level;
} tracker_entry_t;

typedef struct
{
  tracker_entry_t entries[TRACKER_TABLE_SIZE];
  uint32_t follow_s; // TRACKER_DEFAULT_FOLLOW_S unless changed
} tracker_table_t;

void tracker_table_init(tracker_table_t *table);

/*
 * An advertisement of a tracker: adds or updates its entry. Returns its
 * index (-1 when the table is full of more important entries) and sets
 * *new_alert when the tracker just reached LEVEL_ALERT.
 */
int tracker_table_update(tracker_table_t *table, const uint8_t addr[6], const tracker_adv_t *adv, int rssi,
                         uint32_t now_s, bool *new_alert);

/* Forget trackers not seen for TRACKER_EXPIRE_S; recompute the levels. Returns the alert count. */
int tracker_table_tick(tracker_table_t *table, uint32_t now_s);

/* Level from the times the tracker was seen (ignored trackers never alert) */
tracker_level_t tracker_level(const tracker_entry_t *entry, uint32_t follow_s);

/* Toggle ignoring a tracker; recomputes its level */
void tracker_set_ignored(tracker_table_t *table, int index, bool ignored);

/*
 * Indexes of the used entries for the list: alerts first, then watch,
 * then by signal strength. Returns the count.
 */
int tracker_table_sorted(const tracker_table_t *table, int *indexes, int max_count);

/* "AA:BB:CC:DD:EE:FF" */
void format_mac(char *out, size_t out_len, const uint8_t mac[6]);

/* "12s", "5m", "2h05" */
void format_duration(char *out, size_t out_len, uint32_t seconds);
