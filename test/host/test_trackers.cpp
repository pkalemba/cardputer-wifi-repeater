/*
 * Host unit tests of the tracker detector (apps/tracker-detector/src/trackers.cpp)
 */

#include "test.h"

#include "trackers.h"

/* Apple Find My, away from its owner: whole public key (length 0x19) */
static const uint8_t AIRTAG_SEPARATED[] = {
    0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x01, 0x00};
/* Apple Find My with its owner nearby: short form (length 0x02) */
static const uint8_t AIRTAG_NEARBY[] = {0x07, 0xFF, 0x4C, 0x00, 0x12, 0x02, 0x00, 0x01};
/* AirPods proximity pairing (Apple type 0x07): not a tracker */
static const uint8_t AIRPODS[] = {0x0A, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x01, 0x0E, 0x20, 0x55, 0xAA};
/* Google FMDN in unwanted tracking protection mode, after the flags */
static const uint8_t FMDN_UTP[] = {0x02, 0x01, 0x06, 0x07, 0x16, 0xAA, 0xFE, 0x41, 0x11, 0x22, 0x33};
static const uint8_t FMDN[] = {0x07, 0x16, 0xAA, 0xFE, 0x40, 0x11, 0x22, 0x33};
/* Eddystone URL beacon: same service, not a tracker */
static const uint8_t EDDYSTONE_URL[] = {0x03, 0x03, 0xAA, 0xFE, 0x08, 0x16, 0xAA, 0xFE, 0x10, 0xEB, 0x03, 'a', 'b'};
static const uint8_t SMARTTAG[] = {0x02, 0x01, 0x06, 0x05, 0x16, 0x5A, 0xFD, 0x10, 0x20};
static const uint8_t TILE[] = {0x02, 0x01, 0x06, 0x03, 0x03, 0xED, 0xFE};
static const uint8_t CHIPOLO[] = {0x05, 0x03, 0x0F, 0x18, 0x33, 0xFE};
/* Field longer than the data */
static const uint8_t TRUNCATED[] = {0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19};

TEST(test_tracker_parse)
{
  tracker_adv_t adv;
  CHECK(tracker_parse_adv(AIRTAG_SEPARATED, sizeof(AIRTAG_SEPARATED), &adv));
  CHECK_EQ(adv.type, TRACKER_APPLE_FINDMY);
  CHECK_EQ(adv.separated, SEPARATED_YES);

  CHECK(tracker_parse_adv(AIRTAG_NEARBY, sizeof(AIRTAG_NEARBY), &adv));
  CHECK_EQ(adv.type, TRACKER_APPLE_FINDMY);
  CHECK_EQ(adv.separated, SEPARATED_NO);

  CHECK(!tracker_parse_adv(AIRPODS, sizeof(AIRPODS), &adv));

  CHECK(tracker_parse_adv(FMDN_UTP, sizeof(FMDN_UTP), &adv));
  CHECK_EQ(adv.type, TRACKER_GOOGLE_FMDN);
  CHECK_EQ(adv.separated, SEPARATED_YES);
  CHECK(tracker_parse_adv(FMDN, sizeof(FMDN), &adv));
  CHECK_EQ(adv.separated, SEPARATED_UNKNOWN);
  CHECK(!tracker_parse_adv(EDDYSTONE_URL, sizeof(EDDYSTONE_URL), &adv));

  CHECK(tracker_parse_adv(SMARTTAG, sizeof(SMARTTAG), &adv));
  CHECK_EQ(adv.type, TRACKER_SAMSUNG_SMARTTAG);
  CHECK(tracker_parse_adv(TILE, sizeof(TILE), &adv));
  CHECK_EQ(adv.type, TRACKER_TILE);
  CHECK(tracker_parse_adv(CHIPOLO, sizeof(CHIPOLO), &adv)); // second UUID of the list
  CHECK_EQ(adv.type, TRACKER_CHIPOLO);

  CHECK(!tracker_parse_adv(TRUNCATED, sizeof(TRUNCATED), &adv));
  CHECK(!tracker_parse_adv(AIRTAG_SEPARATED, 0, &adv));
  static const uint8_t zero_length[] = {0x00, 0x03, 0x03, 0xED, 0xFE};
  CHECK(!tracker_parse_adv(zero_length, sizeof(zero_length), &adv));
  CHECK_STR(tracker_type_name(TRACKER_TILE), "Tile");
}

/* Advertisements every 20 s for `minutes`, starting at start_s */
static int feed(tracker_table_t *table, const uint8_t addr[6], const tracker_adv_t *adv, uint32_t start_s,
                int minutes, bool *alerted)
{
  int index = -1;
  *alerted = false;
  for (uint32_t t = start_s; t <= start_s + (uint32_t)minutes * 60; t += 20)
  {
    bool new_alert = false;
    index = tracker_table_update(table, addr, adv, -60, t, &new_alert);
    *alerted |= new_alert;
  }
  return index;
}

TEST(test_tracker_follow)
{
  static tracker_table_t table;
  tracker_table_init(&table);
  const uint8_t tag[6] = {0xC0, 0x11, 0x22, 0x33, 0x44, 0x55};
  const tracker_adv_t separated = {TRACKER_APPLE_FINDMY, SEPARATED_YES};
  bool alerted;

  // 3 minutes: just nearby, from 3m20 (a third of 10 minutes): watch, from 10 minutes: alert (once)
  int index = feed(&table, tag, &separated, 1000, 3, &alerted);
  CHECK(index >= 0);
  CHECK_EQ(table.entries[index].level, LEVEL_NEARBY);
  feed(&table, tag, &separated, 1000 + 3 * 60 + 20, 1, &alerted);
  CHECK_EQ(table.entries[index].level, LEVEL_WATCH);
  CHECK(!alerted);
  feed(&table, tag, &separated, 1000 + 4 * 60 + 20, 6, &alerted);
  CHECK_EQ(table.entries[index].level, LEVEL_ALERT);
  CHECK(alerted);
  feed(&table, tag, &separated, 1000 + 10 * 60 + 20, 1, &alerted);
  CHECK(!alerted); // reported once
  CHECK_EQ(tracker_table_tick(&table, 1000 + 12 * 60), 1);

  // Ignored: no alert any more
  tracker_set_ignored(&table, index, true);
  CHECK_EQ(table.entries[index].level, LEVEL_NEARBY);
  CHECK_EQ(tracker_table_tick(&table, 1000 + 12 * 60), 0);
  tracker_set_ignored(&table, index, false);
  CHECK_EQ(table.entries[index].level, LEVEL_ALERT);

  // Forgotten after 30 minutes without an advertisement
  uint32_t last_seen = table.entries[index].last_seen;
  CHECK_EQ(tracker_table_tick(&table, last_seen + TRACKER_EXPIRE_S - 1), 1);
  CHECK_EQ(tracker_table_tick(&table, last_seen + TRACKER_EXPIRE_S), 0);
  CHECK(!table.entries[index].used);
}

TEST(test_tracker_owner_nearby)
{
  static tracker_table_t table;
  tracker_table_init(&table);
  const uint8_t tag[6] = {0xC0, 0x11, 0x22, 0x33, 0x44, 0x66};
  const tracker_adv_t nearby = {TRACKER_APPLE_FINDMY, SEPARATED_NO};
  const tracker_adv_t unknown = {TRACKER_TILE, SEPARATED_UNKNOWN};
  bool alerted;

  // A fellow passenger's AirTag (owner nearby) never alerts
  int index = feed(&table, tag, &nearby, 0, 30, &alerted);
  CHECK(!alerted);
  CHECK_EQ(table.entries[index].level, LEVEL_NEARBY);

  // A Tile does not tell: it can alert
  const uint8_t tile[6] = {0xE1, 0x00, 0x00, 0x00, 0x00, 0x01};
  index = feed(&table, tile, &unknown, 0, 12, &alerted);
  CHECK(alerted);
}

TEST(test_tracker_presence)
{
  static tracker_table_t table;
  tracker_table_init(&table);
  const uint8_t tag[6] = {0xC0, 0x11, 0x22, 0x33, 0x44, 0x77};
  const tracker_adv_t separated = {TRACKER_APPLE_FINDMY, SEPARATED_YES};
  bool alerted;

  // Seen at the start and 15 minutes later only (e.g. same cafe twice): not following
  int index = feed(&table, tag, &separated, 0, 1, &alerted);
  feed(&table, tag, &separated, 15 * 60, 1, &alerted);
  CHECK(!alerted);
  CHECK_EQ(table.entries[index].minutes_seen, 4);
  CHECK_EQ(table.entries[index].level, LEVEL_NEARBY);
}

TEST(test_tracker_sorting_and_full_table)
{
  static tracker_table_t table;
  tracker_table_init(&table);
  const tracker_adv_t separated = {TRACKER_APPLE_FINDMY, SEPARATED_YES};
  bool alerted;

  uint8_t follower[6] = {0xAA, 0, 0, 0, 0, 1};
  int follower_index = feed(&table, follower, &separated, 0, 11, &alerted);
  CHECK(alerted);

  // Fill the table with passing trackers: the alert stays
  for (int i = 0; i < TRACKER_TABLE_SIZE + 5; i++)
  {
    uint8_t addr[6] = {0xBB, 0, 0, 0, (uint8_t)(i >> 8), (uint8_t)i};
    bool new_alert;
    CHECK(tracker_table_update(&table, addr, &separated, -90 + i % 20, 700 + i, &new_alert) >= 0);
  }
  CHECK(table.entries[follower_index].used);
  CHECK_EQ(table.entries[follower_index].addr[0], 0xAA);

  int order[TRACKER_TABLE_SIZE];
  int count = tracker_table_sorted(&table, order, TRACKER_TABLE_SIZE);
  CHECK_EQ(count, TRACKER_TABLE_SIZE);
  CHECK_EQ(order[0], follower_index); // alert first
  for (int i = 2; i < count; i++)
    CHECK(table.entries[order[i - 1]].rssi >= table.entries[order[i]].rssi);
}

TEST(test_tracker_format)
{
  char out[32];
  const uint8_t mac[6] = {0x01, 0xAB, 0x00, 0xFF, 0x10, 0x0C};
  format_mac(out, sizeof(out), mac);
  CHECK_STR(out, "01:AB:00:FF:10:0C");
  format_duration(out, sizeof(out), 42);
  CHECK_STR(out, "42s");
  format_duration(out, sizeof(out), 600);
  CHECK_STR(out, "10m");
  format_duration(out, sizeof(out), 2 * 3600 + 5 * 60 + 30);
  CHECK_STR(out, "2h05");
}

void run_tracker_tests(void)
{
  RUN(test_tracker_parse);
  RUN(test_tracker_follow);
  RUN(test_tracker_owner_nearby);
  RUN(test_tracker_presence);
  RUN(test_tracker_sorting_and_full_table);
  RUN(test_tracker_format);
}
