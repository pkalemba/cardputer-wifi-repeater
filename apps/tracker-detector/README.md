# 🏷️ Tracker detector

Warns you when a Bluetooth tracker seems to **travel with you**: someone's AirTag slipped into
your bag, a SmartTag under the car seat. It listens all the time (Bluetooth only, nothing is
sent) and the detail view helps you find the tracker by its signal strength.

## What it recognizes

| Tracker | How | Tells if the owner is around? |
|---|---|---|
| **AirTag and other Apple Find My accessories** (Chipolo ONE Spot, Pebblebee, ...) | Apple manufacturer data, type `0x12` | ✅ long form = away from its owner |
| **Google Find My Device trackers** (Pebblebee, Chipolo POINT, Motorola moto tag, ...) | service data `0xFEAA`, frame `0x40` / `0x41` | ✅ `0x41` = away from its owner |
| **Samsung Galaxy SmartTag** | service `0xFD5A` | ❌ |
| **Tile** | services `0xFEED` / `0xFEEC` | ❌ |
| **Chipolo** (own app) | service `0xFE33` | ❌ |

## When does it warn?

A tracker gets a colored mark in the list:

| Mark | Meaning |
|---|---|
| grey | just seen - phones and tags of people around you |
| 🟧 orange | around you for 3+ minutes |
| 🟥 red, title bar *N FOLLOWING YOU* | **around you for 10+ minutes** and seen in at least half of those minutes, and not with its owner |

Trackers whose owner is nearby (the short AirTag advertisement) never turn red: they belong to
someone on the same train. Trackers that do not say (SmartTag, Tile) can turn red - if it is
yours or a companion's, press **I** to ignore it. Trackers not heard for 30 minutes are
forgotten.

When a tracker turns red the screen turns on. The screen turns off after 60 s without a key
press (not in the detail view).

**Limits:** SmartTags change their address regularly (about every 15 minutes), so the detector sees a "new"
tag each time and may not warn about them. A tracker that stays silent (or out of range) is
not found. Use it as a hint, together with the tracker alerts of your phone.

## Keys

| Key | Action |
|---|---|
| `Fn` + `;` / `.` | select a tracker |
| `Enter` | detail view: type, address, how long it has been around, signal meter |
| `Esc` / `Backspace` | back to the list |
| `I` | ignore the tracker (yours / a companion's) - press again to stop ignoring |
| `C` | clear the list |
| `?` | help |
| **G0** (all Cardputers) | short press: next tracker / back, hold 1 s: detail view |

The keyboard works on the **Cardputer ADV**; on the original Cardputer use G0.

### Finding the tracker

Open the detail view and walk around: the bar grows as you get closer (signal from
-100 dBm = empty to -30 dBm = full). Tags in a bag or under a seat are a few dB weaker than in
the open - check pockets, linings, the car's wheel arches and the space under the seats.

## Build

```bash
cd apps/tracker-detector
pio run -t upload
```

See the [main README](../../README.md) for pre-built binaries, Launcher and the unit tests
(`test/host/test_trackers.cpp`).
