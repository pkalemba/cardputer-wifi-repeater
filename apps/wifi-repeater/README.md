# 📡 CardRepeater - WiFi Repeater for M5Stack Cardputer

<div align="center">

**Transform your M5Stack Cardputer into a powerful WiFi repeater with NAT routing**

[![ESP32-S3](https://img.shields.io/badge/ESP32-S3-blue.svg)](https://www.espressif.com/en/products/socs/esp32-s3)
[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg)](https://platformio.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](../../LICENSE)

</div>

---

## ✨ Features

### 🔌 Core Functionality
- **WiFi Repeater**: Extends your WiFi network range with NAPT (Network Address Port Translation)
- **Dual Mode Operation**: Functions as both Station (uplink) and Access Point simultaneously
- **Internet Connectivity Check**: HTTP probe (`generate_204`) verifies real internet access
- **DNS Forwarding**: Seamlessly forwards DNS queries from clients to upstream network
- **Auto-reconnect**: never gives up on the uplink - retries with a growing delay (1 s up to 60 s) when the WiFi drops out
- **Subnet conflict handling**: if the uplink network uses the AP's subnet (`192.168.4.x`), the AP moves to `192.168.44.1` (or another free subnet) and the display shows the new address

### 🔐 WireGuard VPN
- **Full tunnel**: all client traffic (`0.0.0.0/0`) is routed through a WireGuard peer
- **Automatic time sync** (SNTP) before the handshake - required by WireGuard
- **Full or split tunnel**: full tunnel sends all client traffic through the VPN; split tunnel only the listed networks (up to 8, e.g. `192.168.1.0/24, 10.0.0.0/8` for the home LAN) - everything else goes directly through the uplink. The display shows `VPN:SPL`
- **Kill switch** (optional, full tunnel): while the tunnel is down, client traffic is blocked instead of going out through the hotel network (DNS included). During captive portal login traffic is let through so the login page can be reached. The display shows `VPN:BLK`
- **Portal aware**: the tunnel takes over routing only once the uplink has real internet access, so hotel/airport login pages stay reachable
- **Optional VPN DNS** offered to clients via DHCP

### 🏨 Captive Portal Support
- **Several saved networks**: up to five uplinks (home, hotel, phone hotspot...). The repeater connects to the strongest one in range and switches when it is gone
- **Uplink MAC address**: factory, custom (e.g. the address of a phone that already passed a hotel login page) or random at every start (for networks that limit free time per device)
- **Open networks**: hotel/airport WiFi without a password works. Leave the uplink password empty, or pick an open network from the scan. With a password saved, the repeater still joins the network if it turns out to be open; enter `-` as the password to remove the saved one
- **Uplink portal detection**: recognizes hotel/airport login pages and shows `LOGIN` on the display; the web UI links to the login page. Signing in once from any client unlocks internet for all clients (they share the repeater's address)
  - several probes (Google, Apple, Microsoft) and a DNS check, so portals that block all traffic before login are recognized too
  - the web UI shows the result of the last check, to see what the network does
- **Automatic login page on clients**: while the uplink needs a login, phones and laptops connected to the repeater show their own "Sign in to network" page with the portal's login page. Works through a small DNS proxy on the repeater (can be switched off in the Device section)
- **Setup captive portal**: in setup mode every DNS name resolves to the repeater, so phones and laptops open the configuration page automatically

### 📡 WiFi Scanning
- **Network picker** in the web UI - press *Scan* and tap a network instead of typing the SSID

### 🖥️ Terminal UI
- **Gruvbox dark theme**: the same palette on the display and in the web panel
- **Real-time Status Display**: 
  - 🟢 Uplink connection status with RSSI signal strength
  - 📶 Live client count
  - 🌐 Internet connectivity indicator (Green = online, Yellow = checking, Orange + `LOGIN` = captive portal, Red + `NO NET` = connected without internet, Red = offline)
  - 🔐 VPN status (`VPN:ON` / `VPN:RDY` / `VPN:..`)
  - 🔋 Battery level (turns red at 15 %)
- **Battery saving** (web UI, Battery section): lower WiFi transmit power (the biggest consumer; costs range) and eco mode (CPU 80-160 MHz instead of 240 MHz). While online, internet access is checked once a minute instead of every 10 s
- **Screen timeout**: the screen turns off after 60 s without activity (configurable, 0 = always on). The **G0** button, a client joining or leaving, and uplink changes turn it back on

### ⚙️ Web Configuration
- **Easy Setup**: Web-UI based configuration interface (because I couldn't get the built in keyboard working)
- **Password protected**: log in with any user name and the admin password set during setup
- **Only from the repeater's WiFi**: the panel does not answer on the uplink side (e.g. to other hotel guests), and after 5 wrong passwords an address has to wait 60 s
- **The repeater's WiFi always has a password** (WPA2, 8-63 characters); older configs with an open network keep working but the display shows `OPEN!` and the panel asks for a password
- **Debug page**: the **Debug info** button shows the uplink connection details (last disconnect reason, security, IP, DNS), the last internet check and the recent log as plain text - easy to copy into a bug report. **Debug + WiFi scan** also lists the networks in range and whether the uplink is among them
- **Build info**: the firmware version (`git describe`: release tag or commit) and build time are shown at the bottom of the page

## 🚀 Quick Start

### Hardware Requirements
- **M5Stack Cardputer** (ESP32-S3 with ST7789 display)
- USB-C cable for programming

### Software Requirements
- [PlatformIO](https://platformio.org/) or Arduino IDE
- ESP-IDF framework

### Installation

1. **Get the firmware**: download `wifi-repeater-…-app.bin` / `…-factory.bin` from the
   [Releases](../../../../releases) (see the [main README](../../README.md#flashing)), or build it:
   ```bash
   git clone https://github.com/pkalemba/cardputer-wifi-repeater.git
   cd cardputer-wifi-repeater/apps/wifi-repeater
   pio run -t upload
   ```

3. **First-time setup**
   - Device will boot into **Setup Mode** (no configuration found)
   - Connect to WiFi network: `CardRepeater`
   - The setup page should open automatically (captive portal); otherwise navigate to `http://192.168.4.1`
   - Press **Scan** to pick your WiFi network and enter its password
   - Device will restart and begin repeating

## 🎮 Usage

### Initial Configuration

When powered on for the first time:

1. **Connect to Setup AP**
   - SSID: `CardRepeater` (open network)
   - The Cardputer display will show setup instructions

2. **Access Web Interface**
   - Opens automatically on most devices, or browse to `http://192.168.4.1`
   - Enter your settings:
     - **Uplink WiFi**: Network to connect to (internet source) - use **Scan** to list nearby networks
     - **Access Point**: Your repeater's network name and password (required, 8-63 characters)
     - **WireGuard VPN** (optional): see below
     - **Device**: admin password for the web panel (required, at least 8 characters) and the screen timeout

3. **Save & Restart**
   - Device automatically reboots into repeater mode

### Normal Operation

After configuration:
- Device connects to upstream WiFi automatically
- Creates access point for client devices
- Display shows live status information
- Web interface remains accessible at `192.168.4.1` for reconfiguration (log in with any user
  name and the admin password). If the uplink network itself uses `192.168.4.x`, the address
  changes to `192.168.44.1` - the display always shows the current one

> Configs saved by older firmware have no admin password: the panel stays open and shows a
> warning until you set one.

### Keyboard (Cardputer ADV)

- **?** (or /): shows these keys on the display; any key closes it
- **Q**: QR code to join the repeater's WiFi - scan it with the phone camera (Android and
  iOS join right away); the network name and password are shown next to it. Any key closes it
- **W**: WiFi menu - pick the uplink network on the device, no phone needed:
  - the list shows the networks in range: `*` = password needed, `+` = already saved, `<` = current
  - arrow keys: **↑ ↓** move, **→** (or Enter) joins, **←** goes back; **R** scans again
  - a secured network that is not saved asks for its password (Shift for capitals and
    symbols, Del erases, **fn + ←** back - the arrow keys type , ; . / there); **P** on a
    saved network types a new password
  - the chosen network is saved as the main network (the previous one stays in the
    saved networks) and the repeater connects to it right away
- **V**: switches the WireGuard VPN on or off (remembered across restarts, same as the
  checkbox in the web UI). The display shows `VPN:OFF` while it is configured but off.
  WireGuard has to be set up in the web UI first.
- **P**: next lower WiFi transmit power (MAX, 17, 15, 13, 11, 8 dBm, then MAX again)
- **E**: eco mode on/off (CPU 80-160 MHz instead of 240 MHz)

P and E take effect right away and are remembered (same settings as the Battery section).
The access point box on the display shows them, e.g. `ECO TX:13`.

The original Cardputer's keyboard (GPIO matrix) is not supported yet.

### G0 Button

- **Press**: turns the screen on
- **Hold for 5 seconds**: erases all settings. A countdown appears after 1 s - release G0
  to cancel. When the settings are erased, release G0 and the device restarts into setup mode.

Don't hold G0 while powering on or resetting: that starts the ESP32-S3 download mode instead.

### Captive Portals (hotels, airports, trains)

When the uplink network requires a login, the display shows an orange dot with `LOGIN`.
Connect a phone or laptop to the repeater: it shows its "Sign in to network" notification
and opens the network's login page, just like on the network itself. You can also open
`http://192.168.4.1` and follow the **Open the login page** link (or open any `http://` page).
After logging in, the status changes to online within ~10 seconds and all clients share the access.

While the uplink is not connected, the display shows why the last attempt failed (for example `network not found (201)` or `wrong password? (15)`).

If the display shows `NO NET`, the repeater got no answer at all. Clients are sent to
`http://192.168.4.1/portal`, which links to the uplink's gateway and to `neverssl.com` - many
portals show their login page there. The **Last check** line in the web UI tells what failed.

To automatically open the login page, the repeater is the DNS server of its clients and
forwards their queries (to the VPN DNS while the tunnel is up). Switch off **Open the
uplink's login page on clients** in the Device section to give clients the uplink's DNS server directly.

### WireGuard VPN

The quickest way: **Import a configuration file (.conf)** in the WireGuard VPN section and
pick the client file (wg-quick, MikroTik or WireGuard app export). The repeater reads it and
fills in the fields - full tunnel for `AllowedIPs = 0.0.0.0/0`, split tunnel for a list of
networks; IPv6 entries are skipped (IPv4 only), a missing `PersistentKeepalive` becomes 25 s.
Check the fields and **Save & Restart**; nothing is saved by the import itself.

The configuration can also come from its **QR code** (WireGuard app, MikroTik): take a photo of
it or pick a screenshot under "... or scan its QR code". This uses the browser's built-in QR
reader (BarcodeDetector), available e.g. in Chrome on Android; other browsers show a note -
use the `.conf` file there. A live camera view is not possible: browsers only allow it on
https pages, and the panel is plain http.

Or fill in the **WireGuard VPN** section by hand with values from your WireGuard client config:

| Web UI field | WireGuard config |
|---|---|
| Interface Address | `[Interface] Address`, e.g. `10.6.0.2/32` |
| Private Key | `[Interface] PrivateKey` |
| Peer Public Key | `[Peer] PublicKey` |
| Preshared Key | `[Peer] PresharedKey` (optional, enter `-` to remove a stored one) |
| Endpoint / Port | `[Peer] Endpoint` host and port |
| Persistent Keepalive | `[Peer] PersistentKeepalive` (default 25) |
| DNS for clients | `[Interface] DNS` (optional, empty = uplink DNS) |

On the server the peer needs `AllowedIPs = <interface address>/32`. The server must
forward/NAT traffic from the tunnel to the internet (as for any full-tunnel client).

Notes:
- Client traffic goes directly through the uplink until the handshake succeeds,
  and while a captive portal requires login - there is no kill switch.
- The tunnel MTU is 1420 while clients use 1500. The repeater clamps the TCP MSS of
  connections through the tunnel to 1380, so TCP segments fit without fragmentation.
- Only IPv4 and one peer are supported.
- WireGuard uses UDP only. Hotel and public networks often block uncommon UDP ports -
  run the server on UDP 443 (or 53, 123, 4500), which usually gets through.
- **Debug info** in the web UI shows the tunnel stage, the resolved endpoint and when the
  last handshake/packet happened. "No answer from the server" means the UDP port is
  most likely blocked by the network (or the endpoint/keys are wrong).

### Performance

The build is tuned for throughput, following Espressif's iperf example for the ESP32-S3:
CPU at 240 MHz, compiler optimization for speed (`-O2`), QIO flash, the lwIP packet
forwarding path in IRAM, WiFi block-ack windows of 16 and the TCP/IP task (NAT and
WireGuard encryption) pinned to core 1 while WiFi runs on core 0. The trade-off is a
somewhat higher power draw.

The ESP32-S3 has a single 2.4 GHz radio: the access point and the uplink share one channel
and every packet crosses the air twice, so a repeater gets at most about half of what a
direct connection would. Place the Cardputer where the uplink signal on the screen is
around -65 dBm or better. To measure, run a speed test or `iperf3` on a device connected
to the repeater.

### Building from Source

This app is one of the [travel apps](../../README.md) in this repository; building, unit
tests, CI binaries and releases are described there. In short:

```bash
cd apps/wifi-repeater
pio run              # build
pio run -t upload    # flash over USB
```

Besides `firmware.bin`, every build writes `.pio/build/m5stack-stamps3/factory.bin`:
a complete image (bootloader + partition table + application) to flash at `0x0`.

### Serial Monitor Commands

View logs at 115200 baud:
```bash
pio device monitor -b 115200
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Ideas for Contributions
- [ ] Add button controls for configuring wifi
- [x] Implement WiFi scanning and network selection
- [x] WireGuard VPN
- [x] Captive portal support
- [ ] Add bandwidth usage statistics
- [ ] Custom themes (amber, blue, etc.)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [ESP-IDF](https://github.com/espressif/esp-idf)
- Designed for [M5Stack Cardputer](https://shop.m5stack.com/products/m5stack-cardputer-kit-w-m5stamps3)
- Inspired by classic terminal aesthetics
- NAPT implementation from ESP-IDF lwIP
- QR codes: [QR Code generator library](https://www.nayuki.io/page/qr-code-generator-library) by Project Nayuki (MIT License), in `lib/cardputer/src/qrcodegen/`

---

## 📮 Support

- **Issues**: [GitHub Issues](https://github.com/ankushKun/cardputer-wifi-repeater/issues)
- email ankush4singh@gmail.com
---

<div align="center">

**Made with 💚 for the M5Stack Cardputer community**

</div>
