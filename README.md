# 📡 CardRepeater - WiFi Repeater for M5Stack Cardputer

<div align="center">

**Transform your M5Stack Cardputer into a powerful WiFi repeater with NAT routing**

[![ESP32-S3](https://img.shields.io/badge/ESP32-S3-blue.svg)](https://www.espressif.com/en/products/socs/esp32-s3)
[![PlatformIO](https://img.shields.io/badge/PlatformIO-Compatible-orange.svg)](https://platformio.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## ✨ Features

### 🔌 Core Functionality
- **WiFi Repeater**: Extends your WiFi network range with NAPT (Network Address Port Translation)
- **Dual Mode Operation**: Functions as both Station (uplink) and Access Point simultaneously
- **Internet Connectivity Check**: HTTP probe (`generate_204`) verifies real internet access
- **DNS Forwarding**: Seamlessly forwards DNS queries from clients to upstream network

### 🔐 WireGuard VPN
- **Full tunnel**: all client traffic (`0.0.0.0/0`) is routed through a WireGuard peer
- **Automatic time sync** (SNTP) before the handshake - required by WireGuard
- **Portal aware**: the tunnel takes over routing only once the uplink has real internet access, so hotel/airport login pages stay reachable
- **Optional VPN DNS** offered to clients via DHCP

### 🏨 Captive Portal Support
- **Uplink portal detection**: recognizes hotel/airport login pages and shows `LOGIN` on the display; the web UI links to the login page. Signing in once from any client unlocks internet for all clients (they share the repeater's address)
- **Setup captive portal**: in setup mode every DNS name resolves to the repeater, so phones and laptops open the configuration page automatically

### 📡 WiFi Scanning
- **Network picker** in the web UI - press *Scan* and tap a network instead of typing the SSID

### 🖥️ Terminal UI
- **Retro CRT Green Theme**: Classic terminal aesthetics on the Cardputer's LCD
- **Real-time Status Display**: 
  - 🟢 Uplink connection status with RSSI signal strength
  - 📶 Live client count
  - 🌐 Internet connectivity indicator (Green = online, Yellow = checking, Orange + `LOGIN` = captive portal, Red = offline)
  - 🔐 VPN status (`VPN:ON` / `VPN:RDY` / `VPN:..`)

### ⚙️ Web Configuration
- **Easy Setup**: Web-UI based configuration interface (because I couldn't get the built in keyboard working)

## 🚀 Quick Start

### Hardware Requirements
- **M5Stack Cardputer** (ESP32-S3 with ST7789 display)
- USB-C cable for programming

### Software Requirements
- [PlatformIO](https://platformio.org/) or Arduino IDE
- ESP-IDF framework

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ankushKun/cardputer-wifi-repeater.git
   cd cardputer-wifi-repeater
   ```

2. **Build and upload**
   ```bash
   # Using PlatformIO
   pio run -t upload
   
   # Or using PlatformIO IDE
   # Click "Upload" button in the IDE
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
     - **Access Point**: Your repeater's network name and password
     - **WireGuard VPN** (optional): see below

3. **Save & Restart**
   - Device automatically reboots into repeater mode

### Normal Operation

After configuration:
- Device connects to upstream WiFi automatically
- Creates access point for client devices
- Display shows live status information
- Web interface remains accessible at `192.168.4.1` for reconfiguration

### Captive Portals (hotels, airports, trains)

When the uplink network requires a login, the display shows an orange dot with `LOGIN`.
Connect any device to the repeater, open `http://192.168.4.1` and follow the
**Open the login page** link (or open any `http://` page). After logging in, the
status changes to online within ~10 seconds and all clients share the access.

### WireGuard VPN

Fill in the **WireGuard VPN** section of the web interface with values from your
WireGuard client config:

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
- The tunnel MTU is 1420. If some websites hang on large transfers, lower the MTU
  of your client devices to 1420.
- Only IPv4 and one peer are supported.

### Building from Source

```bash
# Clone repository
git clone https://github.com/ankushKun/cardputer-wifi-repeater.git
cd cardputer-wifi-repeater

# Install dependencies
pio pkg install

# Build
pio run

# Upload
pio run -t upload

# Monitor serial output
pio device monitor
```

Besides `firmware.bin`, every build writes `.pio/build/m5stack-stamps3/factory.bin`:
a complete image (bootloader + partition table + application) to flash at `0x0`.

### Pre-built Firmware (CI)

GitHub Actions (`.github/workflows/build.yml`) builds every push to `main` and every
pull request. The binaries are attached to the workflow run as the
`cardputer-wifi-repeater-<commit>` artifact; the run summary shows the firmware size.

| File | Flash offset |
|---|---|
| `*-factory.bin` | `0x0` - complete image, use this one |
| `*-app.bin` | `0x10000` - application only |
| `*-bootloader.bin` / `*-partitions.bin` | `0x0` / `0x8000` |
| `*.elf` | not flashed - decodes crash backtraces |

```bash
esptool.py --chip esp32s3 write_flash 0x0 cardputer-wifi-repeater-<version>-factory.bin
```

The factory image can also be flashed from a browser with the
[ESP web flasher](https://espressif.github.io/esptool-js/) at address `0x0`.

Pushing a tag starting with `v` (e.g. `git tag v1.0.0 && git push origin v1.0.0`) also
publishes a GitHub release with the binaries.

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [ESP-IDF](https://github.com/espressif/esp-idf)
- Designed for [M5Stack Cardputer](https://shop.m5stack.com/products/m5stack-cardputer-kit-w-m5stamps3)
- Inspired by classic terminal aesthetics
- NAPT implementation from ESP-IDF lwIP

---

## 📮 Support

- **Issues**: [GitHub Issues](https://github.com/ankushKun/cardputer-wifi-repeater/issues)
- email ankush4singh@gmail.com
---

<div align="center">

**Made with 💚 for the M5Stack Cardputer community**

</div>
