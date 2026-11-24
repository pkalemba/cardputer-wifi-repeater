/*
 * Host unit tests of the room scanner (apps/room-scanner/src/roomscan.cpp)
 */

#include "test.h"

#include "roomscan.h"

static const uint8_t HIKVISION_MAC[6] = {0x28, 0x57, 0xBE, 0x01, 0x02, 0x03};
static const uint8_t ESPRESSIF_MAC[6] = {0x24, 0x0A, 0xC4, 0x11, 0x22, 0x33};
static const uint8_t WYZE_MAC[6] = {0x2C, 0xAA, 0x8E, 0x00, 0x00, 0x01};
static const uint8_t PHONE_MAC[6] = {0x5A, 0x11, 0x22, 0x33, 0x44, 0x55}; // locally administered (random)
static const uint8_t OTHER_MAC[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x01};    // Xerox, not in the table
static const uint8_t HOTEL_AP[6] = {0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC};

/* Beacon of bssid with an SSID (NULL: no SSID element) and a DS parameter set (channel 0: none) */
static size_t make_beacon(uint8_t *buf, const uint8_t bssid[6], const char *ssid, uint8_t channel)
{
  size_t len = 0;
  buf[len++] = 0x80; // management, beacon
  buf[len++] = 0x00;
  buf[len++] = 0;
  buf[len++] = 0;
  memset(buf + len, 0xFF, 6); // broadcast
  len += 6;
  memcpy(buf + len, bssid, 6);
  len += 6;
  memcpy(buf + len, bssid, 6);
  len += 6;
  buf[len++] = 0x10;
  buf[len++] = 0x00;
  memset(buf + len, 0, 12); // timestamp, interval, capabilities
  len += 12;
  if (ssid)
  {
    buf[len++] = 0;
    buf[len++] = (uint8_t)strlen(ssid);
    memcpy(buf + len, ssid, strlen(ssid));
    len += strlen(ssid);
  }
  if (channel)
  {
    buf[len++] = 3;
    buf[len++] = 1;
    buf[len++] = channel;
  }
  return len;
}

/* Data frame from a station to its AP (to DS) or the other way (from DS), padded to len */
static size_t make_data(uint8_t *buf, bool uplink, const uint8_t station[6], const uint8_t bssid[6], size_t len)
{
  memset(buf, 0, len);
  buf[0] = 0x08; // data
  buf[1] = uplink ? 0x01 : 0x02;
  memcpy(buf + 4, uplink ? bssid : station, 6);
  memcpy(buf + 10, uplink ? station : bssid, 6);
  memcpy(buf + 16, bssid, 6);
  return len;
}

TEST(test_oui_lookup)
{
  const oui_vendor_t *v = oui_lookup(HIKVISION_MAC);
  CHECK(v != NULL);
  CHECK_STR(v ? v->name : "", "Hikvision");
  CHECK_EQ(v ? v->category : -1, VENDOR_CAMERA);
  v = oui_lookup(ESPRESSIF_MAC);
  CHECK_STR(v ? v->name : "", "Espressif");
  CHECK_EQ(v ? v->category : -1, VENDOR_IOT);
  v = oui_lookup(WYZE_MAC);
  CHECK_STR(v ? v->name : "", "Wyze");
  CHECK(oui_lookup(OTHER_MAC) == NULL);
  CHECK(oui_lookup(PHONE_MAC) == NULL);
  CHECK(mac_is_random(PHONE_MAC));
  CHECK(!mac_is_random(HIKVISION_MAC));
  const uint8_t multicast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
  CHECK(oui_lookup(multicast) == NULL);
}

TEST(test_camera_ssid)
{
  CHECK(ssid_looks_like_camera("IPC-12AB34"));
  CHECK(ssid_looks_like_camera("HDWiFiCam-8899"));
  CHECK(ssid_looks_like_camera("CAM_00042"));
  CHECK(ssid_looks_like_camera("EZVIZ_C3W"));
  CHECK(ssid_looks_like_camera("My-DVR"));
  CHECK(ssid_looks_like_camera("YiCamera"));
  CHECK(!ssid_looks_like_camera("Hotel Guest"));
  CHECK(!ssid_looks_like_camera("Campus WiFi"));
  CHECK(!ssid_looks_like_camera("Cambridge Inn"));
  CHECK(!ssid_looks_like_camera("Camping Free WiFi")); // "camp" is not a camera...
  CHECK(!ssid_looks_like_camera("TopCIPC"));            // "ipc" only at the start
  CHECK(!ssid_looks_like_camera(""));
}

TEST(test_parse_beacon)
{
  uint8_t buf[128];
  wifi_frame_t frame;
  size_t len = make_beacon(buf, HIKVISION_MAC, "IPC-1234", 6);
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_EQ(frame.kind, FRAME_BEACON);
  CHECK(memcmp(frame.transmitter, HIKVISION_MAC, 6) == 0);
  CHECK_STR(frame.ssid, "IPC-1234");
  CHECK_EQ(frame.channel, 6);

  // Hidden network: empty name or zeros
  len = make_beacon(buf, HOTEL_AP, "", 11);
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_STR(frame.ssid, "");
  len = make_beacon(buf, HOTEL_AP, "\0\0\0\0", 0);
  buf[37] = 4; // SSID length 4, zeros
  memset(buf + 38, 0, 4);
  CHECK(wifi_parse_frame(buf, 38 + 4, &frame));
  CHECK_STR(frame.ssid, "");
  CHECK_EQ(frame.channel, 0);

  // Non-ASCII names are shown with '?'
  len = make_beacon(buf, HOTEL_AP, "Caf\xC3\xA9", 1);
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_STR(frame.ssid, "Caf??");

  // An element longer than the frame stops the parsing, the frame is still a beacon
  len = make_beacon(buf, HOTEL_AP, "Hotel", 1);
  buf[37] = 60;
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_STR(frame.ssid, "");

  // Too short for a beacon body
  CHECK(!wifi_parse_frame(buf, 30, &frame));
}

TEST(test_parse_data)
{
  uint8_t buf[256];
  wifi_frame_t frame;
  size_t len = make_data(buf, true, WYZE_MAC, HOTEL_AP, 200);
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_EQ(frame.kind, FRAME_UPLINK);
  CHECK(memcmp(frame.transmitter, WYZE_MAC, 6) == 0);
  CHECK(memcmp(frame.bssid, HOTEL_AP, 6) == 0);
  CHECK_EQ(frame.length, 200);

  len = make_data(buf, false, WYZE_MAC, HOTEL_AP, 100);
  CHECK(wifi_parse_frame(buf, len, &frame));
  CHECK_EQ(frame.kind, FRAME_DOWNLINK);
  CHECK(memcmp(frame.transmitter, HOTEL_AP, 6) == 0);

  buf[1] = 0x03; // WDS (to and from DS): ignored
  CHECK(!wifi_parse_frame(buf, len, &frame));
  buf[1] = 0x00; // ad hoc: ignored
  CHECK(!wifi_parse_frame(buf, len, &frame));
  buf[0] = 0xD4; // control (ACK): ignored
  CHECK(!wifi_parse_frame(buf, len, &frame));
  CHECK(!wifi_parse_frame(buf, 23, &frame));
}

/* Feed `seconds` of traffic on channel: a beacon of the hotel AP and `bytes_per_s` of uplink from station */
static void feed_stream(room_scan_t *scan, const uint8_t station[6], uint8_t channel, int seconds, int bytes_per_s,
                        int rssi, uint32_t start_s)
{
  uint8_t buf[1600];
  wifi_frame_t frame;
  for (int s = 0; s < seconds; s++)
  {
    size_t len = make_beacon(buf, HOTEL_AP, "Hotel Guest", channel);
    wifi_parse_frame(buf, len, &frame);
    room_scan_frame(scan, &frame, channel, -70, start_s + s);
    for (int sent = 0; sent < bytes_per_s; sent += 1000)
    {
      len = make_data(buf, true, station, HOTEL_AP, 1000);
      wifi_parse_frame(buf, len, &frame);
      room_scan_frame(scan, &frame, channel, rssi, start_s + s);
    }
    room_scan_dwell(scan, channel, 1000);
  }
}

TEST(test_room_scores)
{
  static room_scan_t scan;
  room_scan_init(&scan);

  // A Wyze camera streaming 20 KB/s close by
  feed_stream(&scan, WYZE_MAC, 6, 10, 20000, -45, 100);
  // A phone with a random address uploading a little, far away (on another channel:
  // listening there does not count for the camera's rate)
  feed_stream(&scan, PHONE_MAC, 11, 10, 2000, -80, 100);
  // An ESP32 smart plug, quiet, far away (channel 6)
  uint8_t buf[128];
  wifi_frame_t frame;
  size_t len = make_data(buf, true, ESPRESSIF_MAC, HOTEL_AP, 100);
  wifi_parse_frame(buf, len, &frame);
  room_scan_frame(&scan, &frame, 6, -85, 105);
  // An access point with a camera name
  len = make_beacon(buf, OTHER_MAC, "HDWiFiCam-01", 6);
  wifi_parse_frame(buf, len, &frame);
  room_scan_frame(&scan, &frame, 6, -75, 105);

  CHECK_EQ(room_scan_tick(&scan, 110), 1);

  int order[ROOM_MAX_DEVICES];
  int count = room_scan_sorted(&scan, RISK_NONE, order, ROOM_MAX_DEVICES);
  CHECK_EQ(count, 5); // hotel AP, camera, phone, plug, camera AP

  const room_device_t *cam = &scan.devices[order[0]];
  CHECK(memcmp(cam->mac, WYZE_MAC, 6) == 0);
  CHECK_EQ(cam->risk, RISK_HIGH);
  CHECK(cam->reasons & REASON_CAMERA_VENDOR);
  CHECK(cam->reasons & REASON_STREAMING);
  CHECK(cam->reasons & REASON_STRONG);
  CHECK(cam->upload_rate >= 19000 && cam->upload_rate <= 21000);
  CHECK_STR(cam->ssid, "Hotel Guest"); // the network it uses
  CHECK(!cam->is_ap);

  const room_device_t *cam_ap = &scan.devices[order[1]];
  CHECK_STR(cam_ap->ssid, "HDWiFiCam-01");
  CHECK_EQ(cam_ap->risk, RISK_MEDIUM);
  CHECK_EQ(cam_ap->reasons, REASON_CAMERA_SSID);

  // Only the suspicious ones
  count = room_scan_sorted(&scan, RISK_LOW, order, ROOM_MAX_DEVICES);
  CHECK_EQ(count, 3); // camera, camera AP, smart plug
  const room_device_t *plug = &scan.devices[order[2]];
  CHECK(memcmp(plug->mac, ESPRESSIF_MAC, 6) == 0);
  CHECK_EQ(plug->risk, RISK_LOW);
  CHECK_EQ(plug->reasons, REASON_IOT_CHIP);

  // The phone: not streaming enough, random address
  for (int i = 0; i < ROOM_MAX_DEVICES; i++)
    if (scan.devices[i].used && memcmp(scan.devices[i].mac, PHONE_MAC, 6) == 0)
    {
      CHECK_EQ(scan.devices[i].risk, RISK_NONE);
      CHECK(scan.devices[i].vendor == NULL);
    }

  // Forgotten after ROOM_EXPIRE_S of silence
  room_scan_tick(&scan, 110 + ROOM_EXPIRE_S);
  CHECK_EQ(room_scan_sorted(&scan, RISK_NONE, order, ROOM_MAX_DEVICES), 0);
}

TEST(test_room_rate_needs_dwell)
{
  static room_scan_t scan;
  room_scan_init(&scan);
  // 3 s of heavy upload is not enough to call it a stream
  feed_stream(&scan, ESPRESSIF_MAC, 1, 3, 30000, -80, 0);
  room_scan_tick(&scan, 3);
  int order[ROOM_MAX_DEVICES];
  CHECK(room_scan_sorted(&scan, RISK_LOW, order, ROOM_MAX_DEVICES) == 1);
  CHECK_EQ(scan.devices[order[0]].upload_rate, 0);
  // Time on other channels does not count: switch away and back
  room_scan_dwell(&scan, 6, 10000);
  room_scan_tick(&scan, 4);
  CHECK_EQ(scan.devices[order[0]].upload_rate, 0);
  feed_stream(&scan, ESPRESSIF_MAC, 1, 3, 30000, -80, 5);
  room_scan_tick(&scan, 8);
  CHECK(scan.devices[order[0]].reasons & REASON_STREAMING);
  CHECK_EQ(scan.devices[order[0]].risk, RISK_MEDIUM); // IoT chip + stream, not near
}

TEST(test_room_beacon_channel)
{
  static room_scan_t scan;
  room_scan_init(&scan);
  uint8_t buf[128];
  wifi_frame_t frame;
  // Heard on channel 5, announces channel 6: the device is on 6, the weak signal is not its real one
  size_t len = make_beacon(buf, HOTEL_AP, "Hotel", 6);
  wifi_parse_frame(buf, len, &frame);
  int i = room_scan_frame(&scan, &frame, 5, -90, 0);
  CHECK_EQ(scan.devices[i].channel, 6);
  CHECK_EQ(scan.devices[i].rssi_max, -128);
  room_scan_frame(&scan, &frame, 6, -60, 1);
  CHECK_EQ(scan.devices[i].rssi, -60);
}

TEST(test_room_full_table)
{
  static room_scan_t scan;
  room_scan_init(&scan);
  uint8_t buf[128];
  wifi_frame_t frame;
  size_t len = make_beacon(buf, HIKVISION_MAC, "NVR", 1);
  wifi_parse_frame(buf, len, &frame);
  room_scan_frame(&scan, &frame, 1, -70, 0);
  room_scan_tick(&scan, 0);
  // Many plain devices: the camera stays
  for (int n = 0; n < ROOM_MAX_DEVICES * 2; n++)
  {
    uint8_t mac[6] = {0x00, 0x00, 0x01, 0x10, (uint8_t)(n >> 8), (uint8_t)n};
    len = make_data(buf, true, mac, HOTEL_AP, 100);
    wifi_parse_frame(buf, len, &frame);
    CHECK(room_scan_frame(&scan, &frame, 1, -70, 1 + n) >= 0);
  }
  bool found = false;
  for (int i = 0; i < ROOM_MAX_DEVICES; i++)
    found |= scan.devices[i].used && memcmp(scan.devices[i].mac, HIKVISION_MAC, 6) == 0;
  CHECK(found);
}

TEST(test_reasons_text)
{
  char out[64];
  room_reasons_text(out, sizeof(out), REASON_CAMERA_VENDOR | REASON_STREAMING | REASON_STRONG);
  CHECK_STR(out, "cam-maker streaming near");
  room_reasons_text(out, sizeof(out), 0);
  CHECK_STR(out, "");
  char small[12];
  room_reasons_text(small, sizeof(small), REASON_CAMERA_VENDOR | REASON_STREAMING);
  CHECK_STR(small, "cam-maker");
}

void run_roomscan_tests(void)
{
  RUN(test_oui_lookup);
  RUN(test_camera_ssid);
  RUN(test_parse_beacon);
  RUN(test_parse_data);
  RUN(test_room_scores);
  RUN(test_room_rate_needs_dwell);
  RUN(test_room_beacon_channel);
  RUN(test_room_full_table);
  RUN(test_reasons_text);
}
