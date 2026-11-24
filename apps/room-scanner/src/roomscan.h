/*
 * Hidden camera check of a room: what the Cardputer hears on WiFi
 * (802.11 frames in promiscuous mode) and how suspicious each device is.
 * No ESP-IDF dependencies - unit tested on the host (test/host).
 *
 * A device gets points for:
 *  - a MAC address of a camera maker (Hikvision, Dahua, Wyze, ...) or of a
 *    chip made for cameras, fewer for WiFi chips of cheap smart devices
 *    (Espressif, Tuya, Beken, ...) - oui_table.h
 *  - its own network with a camera-like name (IPC..., ...CAM..., Ezviz...)
 *  - sending a steady stream of data (a camera uploading video)
 *  - a strong signal (it is probably in the room) - only on top of the above
 *
 * This is a heuristic: it misses cameras that record to an SD card without
 * WiFi, cameras on 5 GHz and ones with randomized addresses, and it flags
 * harmless smart plugs. It narrows down where to look - it is no proof.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════
 * MAC address prefixes
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum
{
  VENDOR_CAMERA,     // security cameras, doorbells, recorders
  VENDOR_CAMERA_SOC, // chips made for cameras
  VENDOR_IOT,        // WiFi chips of cheap smart devices
} vendor_category_t;

typedef struct
{
  const char *name;
  vendor_category_t category;
} oui_vendor_t;

/* Vendor of a MAC address, NULL if not in the table (or a randomized address) */
const oui_vendor_t *oui_lookup(const uint8_t mac[6]);

/* Locally administered address: randomized by phones and laptops for privacy */
bool mac_is_random(const uint8_t mac[6]);

/* Network name that sounds like a camera (its setup or direct-connect network) */
bool ssid_looks_like_camera(const char *ssid);

/* ═══════════════════════════════════════════════════════════════════
 * 802.11 frames
 * ═══════════════════════════════════════════════════════════════════ */

typedef enum
{
  FRAME_OTHER = 0,
  FRAME_BEACON,  // beacon or probe response of an access point
  FRAME_UPLINK,  // data from a station to its access point (to DS)
  FRAME_DOWNLINK, // data from an access point to a station (from DS)
} frame_kind_t;

typedef struct
{
  frame_kind_t kind;
  uint8_t transmitter[6];
  uint8_t bssid[6];
  char ssid[33];   // beacons: network name, empty if hidden
  uint8_t channel; // beacons: channel from the DS parameter set, 0 if absent
  uint16_t length; // frame length
} wifi_frame_t;

/* Parse an 802.11 frame (without FCS); false for frames we do not use */
bool wifi_parse_frame(const uint8_t *frame, size_t len, wifi_frame_t *out);

/* ═══════════════════════════════════════════════════════════════════
 * Devices in range
 * ═══════════════════════════════════════════════════════════════════ */

#define ROOM_MAX_DEVICES 64
#define ROOM_EXPIRE_S 300          // forgotten after this long without a frame
#define ROOM_STREAM_BYTES_PER_S 8000 // steady upload of at least ~64 kbit/s: video
#define ROOM_STREAM_MIN_DWELL_MS 5000 // ... measured over at least this long on its channel
#define ROOM_STRONG_RSSI (-55)      // probably in the same room

/* Reasons (bit flags) */
#define REASON_CAMERA_VENDOR 0x01
#define REASON_CAMERA_CHIP 0x02
#define REASON_IOT_CHIP 0x04
#define REASON_CAMERA_SSID 0x08
#define REASON_STREAMING 0x10
#define REASON_STRONG 0x20

typedef enum
{
  RISK_NONE = 0,
  RISK_LOW,
  RISK_MEDIUM,
  RISK_HIGH,
} risk_t;

typedef struct
{
  bool used;
  bool is_ap;
  uint8_t mac[6];
  uint8_t bssid[6]; // stations: their access point
  char ssid[33];    // access points: their network; stations: their AP's when known
  uint8_t channel;
  int8_t rssi;
  int8_t rssi_max;
  uint32_t first_seen; // seconds
  uint32_t last_seen;
  uint32_t frames;
  uint32_t uplink_bytes;     // data frames sent to an access point
  uint32_t dwell_start_ms;   // time spent on its channel when first seen
  uint32_t upload_rate;      // bytes/s while listening on its channel
  const oui_vendor_t *vendor;
  uint8_t reasons;
  uint8_t score;
  risk_t risk;
} room_device_t;

typedef struct
{
  room_device_t devices[ROOM_MAX_DEVICES];
  uint32_t dwell_ms[15]; // time spent listening on each channel (1-14)
  uint32_t frames;       // all frames parsed
} room_scan_t;

void room_scan_init(room_scan_t *scan);

/* Time spent listening on a channel (call when leaving it) */
void room_scan_dwell(room_scan_t *scan, uint8_t channel, uint32_t ms);

/* A parsed frame heard on channel with rssi; returns the device index or -1 */
int room_scan_frame(room_scan_t *scan, const wifi_frame_t *frame, uint8_t channel, int rssi, uint32_t now_s);

/* Forget old devices; recompute upload rates and scores. Returns the count of RISK_HIGH devices. */
int room_scan_tick(room_scan_t *scan, uint32_t now_s);

/* Score and risk of one device from its reasons */
void room_device_score(room_device_t *device);

/*
 * Indexes of the devices at or above min_risk: highest score first, then
 * strongest signal. Returns the count.
 */
int room_scan_sorted(const room_scan_t *scan, risk_t min_risk, int *indexes, int max_count);

/* Short text of the reasons, e.g. "cam-vendor stream near" */
void room_reasons_text(char *out, size_t out_len, uint8_t reasons);
