# 🧳 Cardputer travel apps

<div align="center">

**Firmware for the M5Stack Cardputer that helps on the road**

[![ESP32-S3](https://img.shields.io/badge/ESP32-S3-blue.svg)](https://www.espressif.com/en/products/socs/esp32-s3)
[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg)](https://platformio.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Apps

| App | What it does |
|---|---|
| 📡 [**WiFi repeater**](apps/wifi-repeater/README.md) | Travel router: repeats hotel / airport WiFi for all your devices, WireGuard VPN, captive portal login for everyone at once, web panel |
| 🏷️ [**Tracker detector**](apps/tracker-detector/README.md) | Warns about Bluetooth trackers (AirTag, Google Find My Device, SmartTag, Tile, Chipolo) that travel with you, and helps you find them |
| 📷 [**Room scanner**](apps/room-scanner/README.md) | Checks a hotel room or rental for hidden WiFi cameras and helps you find them |

Each app is a separate firmware. With [Launcher](https://github.com/bmorcelli/Launcher) on the
Cardputer you can keep all of them on the SD card and start the one you need.

All apps share the look (Gruvbox dark), the G0 button (short press / hold) and, on the
**Cardputer ADV**, the keyboard (`Fn` + `;` `.` `,` `/` arrows, `Enter`, `Esc`, `?` for help).

## Flashing

Every [release](../../releases) has two files per app:

| File | How to flash it |
|---|---|
| `<app>-<version>-app.bin` | Cardputer with [Launcher](https://github.com/bmorcelli/Launcher): copy it to the SD card and install it from the `SD` menu, or upload it in Launcher's web interface (`WUI` → `OTA`) |
| `<app>-<version>-factory.bin` | Over USB with the [ESP web flasher](https://espressif.github.io/esptool-js/) or esptool, at address `0x0`. This overwrites the whole flash, Launcher included |

```bash
esptool.py --chip esp32s3 write_flash 0x0 room-scanner-<version>-factory.bin
```

## Repository layout

```
apps/
  wifi-repeater/      one PlatformIO + ESP-IDF project per app:
  tracker-detector/     platformio.ini, sdkconfig, src/, README.md
  room-scanner/
lib/cardputer/        shared code: display (ST7789, font, theme, widgets), battery,
                      G0 button, ADV keyboard (TCA8418, key map), QR codes
scripts/              build helpers (version, factory image), fit check, OUI table generator
test/host/            unit tests of the hardware independent code of all apps
```

A new app: copy `apps/tracker-detector` (the smallest), change the project name in its
`CMakeLists.txt`, add it to the matrix in `.github/workflows/build.yml` and to the table above.
Keep the logic that does not need the hardware in its own file and test it in `test/host`.

## Building

```bash
git clone https://github.com/pkalemba/cardputer-wifi-repeater.git
cd cardputer-wifi-repeater/apps/room-scanner   # or another app
pio run                  # build
pio run -t upload        # flash over USB
pio device monitor       # logs, 115200 baud
```

Besides `firmware.bin`, every build writes `.pio/build/m5stack-stamps3/factory.bin`: a complete
image (bootloader + partition table + application) to flash at `0x0`.

### Unit tests

The hardware independent code (form decoding, DNS, MSS clamping, WiFi menu, key map, tracker
recognition and the "follows you" logic, 802.11 frame parsing and camera scoring) has host unit
tests, built with AddressSanitizer and UndefinedBehaviorSanitizer. CI runs them on every push:

```bash
make -C test/host
```

### Pre-built firmware (CI)

GitHub Actions (`.github/workflows/build.yml`) builds every app on every push to `main` and
every pull request, and checks that it fits the Cardputer (see below). The binaries are attached
to the workflow run as `<app>-<commit>` artifacts:

| File | Flash offset |
|---|---|
| `*-factory.bin` | `0x0` - complete image, for flashing over USB |
| `*-app.bin` | `0x10000` - application only, the one to install with Launcher |
| `*-bootloader.bin` / `*-partitions.bin` | `0x0` / `0x8000` |
| `*.elf` | not flashed - decodes crash backtraces |
| `*.map` | not flashed - linker map for memory analysis with `esp-idf-size` |

To publish a release, create one on GitHub (*Releases* → *Draft a new release*, type a new
tag such as `v1.1.0`, *Publish release*) or push a tag starting with `v`
(`git tag v1.1.0 && git push origin v1.1.0`). CI builds that commit and attaches the app and
factory images of every app a few minutes later.

### Does it fit the Cardputer?

After every build `scripts/check_fit.py` checks the firmware against the Cardputer
(ESP32-S3FN8: 8 MB flash, no PSRAM) and fails the CI run when it would not work:

| Check | Fails when |
|---|---|
| Chip / PSRAM | the target is not `esp32s3` or the configuration needs PSRAM |
| Bootloader | it reaches into the partition table at `0x8000` |
| Application | it is larger than its partition (warning from 90 %) |
| Partition table | it ends beyond the configured flash size or the 8 MB chip |
| Factory image | it is larger than the flash |
| Free internal RAM | less than 128 KiB is left for the heap (warning below 192 KiB) - the display framebuffer, WiFi / Bluetooth and the network stack allocate at runtime |

The results are in the run summary. To run the check locally after `pio run` in an app folder:

```bash
pip install esp-idf-size   # needed for the RAM check
python ../../scripts/check_fit.py
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [ESP-IDF](https://github.com/espressif/esp-idf) (lwIP NAPT, NimBLE)
- Designed for [M5Stack Cardputer](https://shop.m5stack.com/products/m5stack-cardputer-kit-w-m5stamps3)
- WiFi repeater originally by [ankushKun](https://github.com/ankushKun/cardputer-wifi-repeater)
- QR codes: [QR Code generator library](https://www.nayuki.io/page/qr-code-generator-library) by Project Nayuki (MIT License), in `lib/cardputer/src/qrcodegen/`
- MAC address prefixes: [IEEE MA-L registry](https://standards-oui.ieee.org/)
