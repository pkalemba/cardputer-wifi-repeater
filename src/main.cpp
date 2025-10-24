#include <Arduino.h>
#include <M5Cardputer.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <esp_wifi.h>

DNSServer dnsServer;

// Uplink WiFi credentials
const char *ssid = "weeblet";
const char *password = "niconiconii";

// Access Point configuration
const char *ap_ssid = "NINTENDO_WIFI";
const char *ap_password = ""; // Open network (no password)

// AP IP configuration
IPAddress ap_ip(192, 168, 4, 1);
IPAddress ap_gateway(192, 168, 4, 1);
IPAddress ap_subnet(255, 255, 255, 0);

void displayStatus(const char *message, uint16_t color = TFT_WHITE)
{
  M5Cardputer.Display.setTextColor(color);
  M5Cardputer.Display.println(message);
  Serial.println(message);
}

void setup()
{
  // Initialize Serial for debugging
  Serial.begin(115200);
  delay(100);

  // Initialize M5 Cardputer
  auto cfg = M5.config();
  M5Cardputer.begin(cfg);

  // Initialize the display
  M5Cardputer.Display.setRotation(1);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.fillScreen(TFT_BLACK);
  M5Cardputer.Display.setCursor(0, 0);

  displayStatus("=== WiFi Repeater ===", TFT_CYAN);
  displayStatus("");

  // Disconnect from any previous WiFi
  WiFi.disconnect(true);
  delay(100);

  // Set WiFi mode to AP+STA (Access Point + Station)
  WiFi.mode(WIFI_AP_STA);

  // ===== Connect to Uplink WiFi (Station Mode) =====
  displayStatus("Connecting to uplink:", TFT_YELLOW);
  displayStatus(ssid, TFT_WHITE);
  displayStatus("");

  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30)
  {
    delay(500);
    M5Cardputer.Display.print(".");
    Serial.print(".");
    attempts++;
  }

  displayStatus("");
  displayStatus("");

  if (WiFi.status() == WL_CONNECTED)
  {
    displayStatus("Uplink Connected!", TFT_GREEN);
    displayStatus("");
    displayStatus("STA IP:", TFT_CYAN);
    displayStatus(WiFi.localIP().toString().c_str(), TFT_WHITE);
    displayStatus("");
    displayStatus("Signal:", TFT_CYAN);
    String rssi = String(WiFi.RSSI()) + " dBm";
    displayStatus(rssi.c_str(), TFT_WHITE);

    // ===== Configure Access Point =====
    displayStatus("");
    displayStatus("Starting AP...", TFT_YELLOW);

    // Configure AP IP address
    WiFi.softAPConfig(ap_ip, ap_gateway, ap_subnet);

    // Start the Access Point (open network, no password)
    bool apStarted = WiFi.softAP(ap_ssid, ap_password);

    if (apStarted)
    {
      displayStatus("");
      displayStatus("AP Started!", TFT_GREEN);
      displayStatus("");
      displayStatus("AP SSID:", TFT_MAGENTA);
      displayStatus(ap_ssid, TFT_WHITE);
      displayStatus("");
      displayStatus("AP IP:", TFT_CYAN);
      displayStatus(WiFi.softAPIP().toString().c_str(), TFT_WHITE);

      // ===== Enable DNS Server and Routing =====
      Serial.println("\nEnabling DNS forwarding and routing...");

      // Start DNS server on port 53
      dnsServer.start(53, "*", ap_ip);

      // Enable IP forwarding at WiFi level
      esp_wifi_set_ps(WIFI_PS_NONE); // Disable power saving for better performance

      Serial.println("DNS and routing enabled!");

      displayStatus("");
      displayStatus("Routing Enabled!", TFT_GREEN);
      displayStatus("Repeater Ready!", TFT_YELLOW);

      Serial.println("WiFi Repeater is ready!");
      Serial.print("Connect devices to: ");
      Serial.println(ap_ssid);
    }
    else
    {
      displayStatus("AP Failed!", TFT_RED);
    }
  }
  else
  {
    displayStatus("Uplink Failed!", TFT_RED);
    displayStatus("Check credentials", TFT_YELLOW);
  }
}

void updateDisplay()
{
  M5Cardputer.Display.fillScreen(TFT_BLACK);
  M5Cardputer.Display.setCursor(0, 0);

  // Title
  displayStatus("=== WiFi Repeater ===", TFT_CYAN);
  displayStatus("");

  // Uplink Status
  displayStatus("--- UPLINK ---", TFT_YELLOW);
  if (WiFi.status() == WL_CONNECTED)
  {
    displayStatus("Status: Connected", TFT_GREEN);

    String uplinkInfo = "SSID: ";
    uplinkInfo += ssid;
    displayStatus(uplinkInfo.c_str(), TFT_WHITE);

    String staIP = "IP: ";
    staIP += WiFi.localIP().toString();
    displayStatus(staIP.c_str(), TFT_WHITE);

    String rssi = "Signal: ";
    rssi += String(WiFi.RSSI());
    rssi += " dBm";
    displayStatus(rssi.c_str(), TFT_WHITE);
  }
  else
  {
    displayStatus("Status: Disconnected", TFT_RED);
    displayStatus("Reconnecting...", TFT_YELLOW);
  }

  displayStatus("");

  // Access Point Status
  displayStatus("--- ACCESS POINT ---", TFT_YELLOW);
  displayStatus("SSID: NINTENDO_WIFI", TFT_MAGENTA);

  String apIP = "IP: ";
  apIP += WiFi.softAPIP().toString();
  displayStatus(apIP.c_str(), TFT_WHITE);

  int clients = WiFi.softAPgetStationNum();
  String clientInfo = "Clients: ";
  clientInfo += String(clients);
  displayStatus(clientInfo.c_str(), clients > 0 ? TFT_GREEN : TFT_WHITE);

  displayStatus("");
  displayStatus("Routing: Active", TFT_GREEN);
}

void loop()
{
  M5Cardputer.update();

  // Process DNS requests
  dnsServer.processNextRequest();

  // Monitor WiFi connection status and update display
  static unsigned long lastCheck = 0;
  if (millis() - lastCheck > 2000)
  {
    lastCheck = millis();

    // Attempt reconnect if disconnected
    if (WiFi.status() != WL_CONNECTED)
    {
      Serial.println("Uplink WiFi disconnected! Attempting reconnect...");
      WiFi.begin(ssid, password);
    }
    else
    {
      Serial.print("Uplink OK | RSSI: ");
      Serial.print(WiFi.RSSI());
      Serial.print(" dBm | AP Clients: ");
      Serial.println(WiFi.softAPgetStationNum());
    }

    // Update display with current status
    updateDisplay();
  }

  delay(10);
}