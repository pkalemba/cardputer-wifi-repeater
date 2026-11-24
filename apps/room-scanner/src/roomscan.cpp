/*
 * Hidden camera check - see roomscan.h
 */

#include "roomscan.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "oui_table.h"

/* ═══════════════════════════════════════════════════════════════════
 * MAC address prefixes and network names
 * ═══════════════════════════════════════════════════════════════════ */

bool mac_is_random(const uint8_t mac[6]) { return (mac[0] & 0x02) != 0; }

const oui_vendor_t *oui_lookup(const uint8_t mac[6])
{
  if (mac_is_random(mac) || (mac[0] & 0x01))
    return NULL;
  uint32_t oui = (uint32_t)mac[0] << 16 | (uint32_t)mac[1] << 8 | mac[2];
  int low = 0;
  int high = (int)(sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0])) - 1;
  while (low <= high)
  {
    int mid = (low + high) / 2;
    uint32_t mid_oui = OUI_TABLE[mid] >> 8;
    if (mid_oui == oui)
      return &OUI_VENDORS[OUI_TABLE[mid] & 0xFF];
    if (mid_oui < oui)
      low = mid + 1;
    else
      high = mid - 1;
  }
  return NULL;
}

bool ssid_looks_like_camera(const char *ssid)
{
  char lower[33];
  size_t len = 0;
  for (; ssid[len] && len < sizeof(lower) - 1; len++)
    lower[len] = (char)tolower((unsigned char)ssid[len]);
  lower[len] = '\0';
  if (len == 0)
    return false;

  // Camera brands and recorders anywhere in the name
  static const char *const words[] = {"ezviz", "hikvision", "dahua", "imou", "reolink", "wyze", "dvr", "nvr"};
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
    if (strstr(lower, words[i]))
      return true;

  // "IPC..." (IP camera setup networks)
  if (strncmp(lower, "ipc", 3) == 0)
    return true;

  // "cam" (IPCAM, HDWiFiCam, CAM_1234, YiCamera) - but not "camp"/"campus"/"cambridge"
  for (const char *p = strstr(lower, "cam"); p; p = strstr(p + 1, "cam"))
    if (p[3] != 'p' && p[3] != 'b')
      return true;
  return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * 802.11 frames
 * ═══════════════════════════════════════════════════════════════════ */

#define FC_TYPE_MGMT 0
#define FC_TYPE_DATA 2
#define MGMT_PROBE_RESPONSE 5
#define MGMT_BEACON 8
#define HEADER_LEN 24
#define BEACON_FIXED_LEN 12 // timestamp, interval, capabilities
#define IE_SSID 0
#define IE_DS_PARAMETER 3

bool wifi_parse_frame(const uint8_t *frame, size_t len, wifi_frame_t *out)
{
  if (len < HEADER_LEN)
    return false;
  uint8_t type = (frame[0] >> 2) & 0x03;
  uint8_t subtype = (frame[0] >> 4) & 0x0F;
  bool to_ds = frame[1] & 0x01;
  bool from_ds = frame[1] & 0x02;
  const uint8_t *addr1 = frame + 4;
  const uint8_t *addr2 = frame + 10;
  const uint8_t *addr3 = frame + 16;

  memset(out, 0, sizeof(*out));
  out->length = (uint16_t)(len > 0xFFFF ? 0xFFFF : len);

  if (type == FC_TYPE_MGMT && (subtype == MGMT_BEACON || subtype == MGMT_PROBE_RESPONSE))
  {
    if (len < HEADER_LEN + BEACON_FIXED_LEN)
      return false;
    out->kind = FRAME_BEACON;
    memcpy(out->transmitter, addr2, 6);
    memcpy(out->bssid, addr3, 6);

    // Information elements: [id][length][data]
    size_t pos = HEADER_LEN + BEACON_FIXED_LEN;
    while (pos + 2 <= len)
    {
      uint8_t id = frame[pos];
      uint8_t ie_len = frame[pos + 1];
      if (pos + 2 + ie_len > len)
        break;
      const uint8_t *data = frame + pos + 2;
      if (id == IE_SSID && ie_len <= 32)
      {
        // Hidden networks send an empty name or zeros
        bool printable = ie_len > 0 && data[0] != 0;
        for (int i = 0; i < ie_len && printable; i++)
          printable = data[i] >= 0x20 && data[i] < 0x7F;
        if (printable)
        {
          memcpy(out->ssid, data, ie_len);
          out->ssid[ie_len] = '\0';
        }
        else if (ie_len > 0 && data[0] != 0)
        {
          // UTF-8 or other bytes the display cannot show
          for (int i = 0; i < ie_len; i++)
            out->ssid[i] = data[i] >= 0x20 && data[i] < 0x7F ? (char)data[i] : '?';
          out->ssid[ie_len] = '\0';
        }
      }
      else if (id == IE_DS_PARAMETER && ie_len == 1)
      {
        out->channel = data[0];
      }
      pos += 2 + ie_len;
    }
    return true;
  }

  if (type == FC_TYPE_DATA)
  {
    if (to_ds && !from_ds)
    {
      out->kind = FRAME_UPLINK;
      memcpy(out->transmitter, addr2, 6);
      memcpy(out->bssid, addr1, 6);
      return true;
    }
    if (!to_ds && from_ds)
    {
      out->kind = FRAME_DOWNLINK;
      memcpy(out->transmitter, addr2, 6);
      memcpy(out->bssid, addr2, 6);
      return true;
    }
  }
  return false; // control frames, other management frames, WDS, ad hoc
}

/* ═══════════════════════════════════════════════════════════════════
 * Devices
 * ═══════════════════════════════════════════════════════════════════ */

void room_scan_init(room_scan_t *scan) { memset(scan, 0, sizeof(*scan)); }

void room_scan_dwell(room_scan_t *scan, uint8_t channel, uint32_t ms)
{
  if (channel >= 1 && channel <= 14)
    scan->dwell_ms[channel] += ms;
}

void room_device_score(room_device_t *d)
{
  uint8_t reasons = 0;
  if (d->vendor)
  {
    switch (d->vendor->category)
    {
    case VENDOR_CAMERA:
      reasons |= REASON_CAMERA_VENDOR;
      break;
    case VENDOR_CAMERA_SOC:
      reasons |= REASON_CAMERA_CHIP;
      break;
    case VENDOR_IOT:
      reasons |= REASON_IOT_CHIP;
      break;
    }
  }
  if (d->is_ap && ssid_looks_like_camera(d->ssid))
    reasons |= REASON_CAMERA_SSID;
  if (d->upload_rate >= ROOM_STREAM_BYTES_PER_S)
    reasons |= REASON_STREAMING;

  uint8_t score = 0;
  if (reasons & REASON_CAMERA_VENDOR)
    score += 4;
  if (reasons & REASON_CAMERA_CHIP)
    score += 3;
  if (reasons & REASON_IOT_CHIP)
    score += 1;
  if (reasons & REASON_CAMERA_SSID)
    score += 3;
  if (reasons & REASON_STREAMING)
    score += 2;
  // A strong signal only matters for devices that are suspicious anyway
  if (score > 0 && d->rssi_max >= ROOM_STRONG_RSSI)
  {
    reasons |= REASON_STRONG;
    score += 1;
  }

  d->reasons = reasons;
  d->score = score;
  if (score >= 4)
    d->risk = RISK_HIGH;
  else if (score >= 2)
    d->risk = RISK_MEDIUM;
  else if (score >= 1)
    d->risk = RISK_LOW;
  else
    d->risk = RISK_NONE;
}

static int find_device(room_scan_t *scan, const uint8_t mac[6])
{
  for (int i = 0; i < ROOM_MAX_DEVICES; i++)
    if (scan->devices[i].used && memcmp(scan->devices[i].mac, mac, 6) == 0)
      return i;
  return -1;
}

/* Slot for a new device: a free one, else the least suspicious device heard longest ago */
static int new_slot(room_scan_t *scan)
{
  int victim = -1;
  for (int i = 0; i < ROOM_MAX_DEVICES; i++)
  {
    room_device_t *d = &scan->devices[i];
    if (!d->used)
      return i;
    if (victim < 0 || d->score < scan->devices[victim].score ||
        (d->score == scan->devices[victim].score && d->last_seen < scan->devices[victim].last_seen))
      victim = i;
  }
  return victim;
}

int room_scan_frame(room_scan_t *scan, const wifi_frame_t *frame, uint8_t channel, int rssi, uint32_t now_s)
{
  scan->frames++;
  if (frame->kind == FRAME_OTHER || (frame->transmitter[0] & 0x01)) // group addresses never transmit
    return -1;

  int index = find_device(scan, frame->transmitter);
  if (index < 0)
  {
    index = new_slot(scan);
    room_device_t *d = &scan->devices[index];
    memset(d, 0, sizeof(*d));
    d->used = true;
    memcpy(d->mac, frame->transmitter, 6);
    d->first_seen = now_s;
    d->rssi_max = -128;
    d->vendor = oui_lookup(d->mac);
  }

  room_device_t *d = &scan->devices[index];
  if (frame->kind == FRAME_BEACON || frame->kind == FRAME_DOWNLINK)
    d->is_ap = true;
  if (frame->kind == FRAME_BEACON && frame->ssid[0])
    snprintf(d->ssid, sizeof(d->ssid), "%s", frame->ssid);
  if (frame->kind == FRAME_UPLINK)
    memcpy(d->bssid, frame->bssid, 6);

  // Beacons can be heard on neighbouring channels: trust the channel they announce
  uint8_t device_channel = frame->kind == FRAME_BEACON && frame->channel ? frame->channel : channel;
  if (device_channel >= 1 && device_channel <= 14 && device_channel != d->channel)
  {
    // New (or changed) channel: measure the upload from here
    d->channel = device_channel;
    d->uplink_bytes = 0;
    d->upload_rate = 0;
    d->dwell_start_ms = scan->dwell_ms[device_channel];
  }

  if (frame->kind == FRAME_UPLINK)
    d->uplink_bytes += frame->length;
  // Only frames heard on the device's own channel tell its real signal strength
  if (channel == d->channel || frame->kind != FRAME_BEACON)
  {
    if (rssi < -128)
      rssi = -128;
    if (rssi > 0)
      rssi = 0;
    d->rssi = (int8_t)rssi;
    if (d->rssi > d->rssi_max)
      d->rssi_max = d->rssi;
  }
  d->frames++;
  d->last_seen = now_s;
  return index;
}

int room_scan_tick(room_scan_t *scan, uint32_t now_s)
{
  int high = 0;
  for (int i = 0; i < ROOM_MAX_DEVICES; i++)
  {
    room_device_t *d = &scan->devices[i];
    if (!d->used)
      continue;
    if (now_s - d->last_seen >= ROOM_EXPIRE_S)
    {
      d->used = false;
      continue;
    }

    // Upload rate while we listened on its channel
    if (d->channel >= 1 && d->channel <= 14)
    {
      uint32_t dwell = scan->dwell_ms[d->channel] - d->dwell_start_ms;
      if (dwell >= ROOM_STREAM_MIN_DWELL_MS)
        d->upload_rate = (uint32_t)((uint64_t)d->uplink_bytes * 1000 / dwell);
    }

    // Stations: the name of their network
    if (!d->is_ap && !d->ssid[0])
    {
      int ap = find_device(scan, d->bssid);
      if (ap >= 0 && ap != i && scan->devices[ap].ssid[0])
        memcpy(d->ssid, scan->devices[ap].ssid, sizeof(d->ssid)); // both 33 bytes, terminated
    }

    room_device_score(d);
    if (d->risk == RISK_HIGH)
      high++;
  }
  return high;
}

static bool sorts_before(const room_device_t *a, const room_device_t *b)
{
  if (a->score != b->score)
    return a->score > b->score;
  return a->rssi > b->rssi;
}

int room_scan_sorted(const room_scan_t *scan, risk_t min_risk, int *indexes, int max_count)
{
  int count = 0;
  for (int i = 0; i < ROOM_MAX_DEVICES && count < max_count; i++)
  {
    const room_device_t *d = &scan->devices[i];
    if (!d->used || d->risk < min_risk)
      continue;
    int pos = count++;
    while (pos > 0 && sorts_before(d, &scan->devices[indexes[pos - 1]]))
    {
      indexes[pos] = indexes[pos - 1];
      pos--;
    }
    indexes[pos] = i;
  }
  return count;
}

void room_reasons_text(char *out, size_t out_len, uint8_t reasons)
{
  static const struct
  {
    uint8_t flag;
    const char *text;
  } names[] = {
      {REASON_CAMERA_VENDOR, "cam-maker"}, {REASON_CAMERA_CHIP, "cam-chip"}, {REASON_IOT_CHIP, "iot-chip"},
      {REASON_CAMERA_SSID, "cam-name"},    {REASON_STREAMING, "streaming"}, {REASON_STRONG, "near"},
  };
  size_t pos = 0;
  out[0] = '\0';
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    if (!(reasons & names[i].flag))
      continue;
    int written = snprintf(out + pos, out_len - pos, "%s%s", pos ? " " : "", names[i].text);
    if (written < 0 || (size_t)written >= out_len - pos)
    {
      out[pos] = '\0'; // no half words
      break;
    }
    pos += (size_t)written;
  }
}
