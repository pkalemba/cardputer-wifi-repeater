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
- **Internet Connectivity Check**: Automatic ping tests to verify real internet access
- **DNS Forwarding**: Seamlessly forwards DNS queries from clients to upstream network

### 🖥️ Terminal UI
- **Retro CRT Green Theme**: Classic terminal aesthetics on the Cardputer's LCD
- **Real-time Status Display**: 
  - 🟢 Uplink connection status with RSSI signal strength
  - 📶 Live client count
  - 🌐 Internet connectivity indicator (Green/Yellow/Red)

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
   - Open browser and navigate to: `http://192.168.4.1`
   - Configure your WiFi settings
   - Device will restart and begin repeating

## 🎮 Usage

### Initial Configuration

When powered on for the first time:

1. **Connect to Setup AP**
   - SSID: `CardRepeater` (open network)
   - The Cardputer display will show setup instructions

2. **Access Web Interface**
   - Open browser: `http://192.168.4.1`
   - Enter your settings:
     - **Uplink WiFi**: Network to connect to (internet source)
     - **Access Point**: Your repeater's network name and password

3. **Save & Restart**
   - Device automatically reboots into repeater mode

### Normal Operation

After configuration:
- Device connects to upstream WiFi automatically
- Creates access point for client devices
- Display shows live status information
- Web interface remains accessible at `192.168.4.1` for reconfiguration

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
- [ ] Implement WiFi scanning and network selection
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
