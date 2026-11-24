# 📷 Room scanner

A quick check of a **hotel room or rental for hidden WiFi cameras**. The Cardputer listens to
WiFi on channels 1-13 (promiscuous mode - nothing is sent, no network is joined) and lists
the devices it hears, the most suspicious first. The detail view stays on the device's
channel and shows its signal strength, so you can walk around the room and find it.

## What makes a device suspicious

| Reason | Shown as | Points |
|---|---|---|
| MAC address of a camera maker: Hikvision, Ezviz, Dahua, Uniview, Hanwha, Axis, Vivotek, Amcrest, Reolink, Lorex, Wyze, Ring, Blink, Arlo, YI | `cam-maker` | 4 |
| MAC address of a chip made for cameras: Ingenic, Goke | `cam-chip` | 3 |
| Its own network with a camera-like name: `IPC…`, `…CAM…`, `HDWiFiCam`, `EZVIZ_…`, `…DVR`, ... | `cam-name` | 3 |
| Sends a steady stream of data (8+ KB/s while we listen on its channel) - video upload | `streaming` | 2 |
| WiFi chip of cheap smart devices: Espressif, Tuya, Beken, Bilian, HiSilicon | `iot-chip` | 1 |
| Strong signal (-55 dBm or more): probably in the room - only on top of another reason | `near` | +1 |

**4+ points: red**, 2-3: orange, 1: yellow. The list shows the devices with at least one
point; **A** shows all devices. The MAC prefixes come from the IEEE registry
(`scripts/gen_oui_table.py` → `src/oui_table.h`).

## How to check a room

1. Start it in the room and wait **a minute or two**: it hops through 13 channels and needs
   a few seconds on each to measure uploads.
2. Look at the red and orange devices. A camera that uploads video shows `streaming`; one close
   by also `near`.
3. Open the detail view (`Enter`) and walk around the room: the bar grows as you get closer.
   Typical hiding places: smoke detectors, alarm clocks, USB chargers, TV boxes, air
   fresheners, picture frames.

**It is a hint, not a proof.** It cannot find cameras that record to an SD card without WiFi,
cameras on 5 GHz or with a wired connection, and it flags harmless smart plugs and light bulbs
(`iot-chip`). Phones and laptops use random addresses (shown as `rnd`) and are not matched
to makers. Also look for the small lens reflection with your phone's flashlight.

## Keys

| Key | Action |
|---|---|
| `Fn` + `;` / `.` | select a device |
| `Enter` | detail view: address, maker, network, channel, upload rate, reasons, signal meter (stays on its channel) |
| `Esc` / `Backspace` | back to the list (channel hopping again) |
| `A` | all devices / only suspicious ones |
| `C` | clear the list |
| `?` | help |
| **G0** (all Cardputers) | short press: next device / back, hold 1 s: detail view |

The keyboard works on the **Cardputer ADV**; on the original Cardputer use G0.

## Build

```bash
cd apps/room-scanner
pio run -t upload
```

See the [main README](../../README.md) for pre-built binaries, Launcher and the unit tests
(`test/host/test_roomscan.cpp`).

To refresh the MAC prefixes from the IEEE registry:

```bash
curl -O https://standards-oui.ieee.org/oui/oui.txt
python scripts/gen_oui_table.py oui.txt > apps/room-scanner/src/oui_table.h
```
