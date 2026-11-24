/*
 * Host unit tests for the hardware independent parts of the apps:
 * the WiFi repeater (netutil, wifi_menu), the shared keyboard map and QR
 * code generator, the tracker detector (test_trackers.cpp) and the room
 * scanner (test_roomscan.cpp). Run with `make -C test/host`.
 */

#include "test.h"

#include "netutil.h"
#include "qrcodegen/qrcodegen.h"
#include "wifi_menu.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int checks = 0;
int failures = 0;

static uint32_t ip(const char *text) { return inet_addr(text); }

/* ═══════════════════════════════ form data ═══════════════════════════════ */

TEST(test_url_decode)
{
  char out[64];
  url_decode(out, "a%20b+c%2Fd%3a");
  CHECK_STR(out, "a b c/d:");
  url_decode(out, "100%");  // incomplete escape stays as is
  CHECK_STR(out, "100%");
  url_decode(out, "%zz");
  CHECK_STR(out, "%zz");
}

TEST(test_parse_query_param)
{
  const char *body = "ssid=Hotel+Wifi&pass=p%40ss&ssid2=&wg_dns=1.1.1.1";
  char out[32];
  CHECK(parse_query_param(body, "ssid", out, sizeof(out)));
  CHECK_STR(out, "Hotel Wifi");
  CHECK(parse_query_param(body, "pass", out, sizeof(out)));
  CHECK_STR(out, "p@ss");
  CHECK(parse_query_param(body, "ssid2", out, sizeof(out))); // present but empty
  CHECK_STR(out, "");
  CHECK(!parse_query_param(body, "dns", out, sizeof(out)));   // only whole field names
  CHECK(!parse_query_param(body, "missing", out, sizeof(out)));
  CHECK(!parse_query_param(NULL, "ssid", out, sizeof(out)));

  char small[5];
  CHECK(parse_query_param("k=abcdefgh", "k", small, sizeof(small)));
  CHECK_STR(small, "abcd"); // truncated to the buffer
}

TEST(test_parse_mac)
{
  uint8_t mac[6];
  CHECK(parse_mac("A8:BB:CC:DD:EE:FF", mac));
  CHECK_EQ(mac[0], 0xA8);
  CHECK_EQ(mac[5], 0xFF);
  CHECK(parse_mac("a2-b7-28-a4-2e-e3", mac));
  CHECK_EQ(mac[1], 0xB7);
  CHECK(parse_mac("a2b728a42ee3", mac));
  CHECK(!parse_mac("A2:B7:28:A4:2E", mac));       // too short
  CHECK(!parse_mac("A2:B7:28:A4:2E:E3:11", mac)); // too long
  CHECK(!parse_mac("zz:b7:28:a4:2e:e3", mac));
  CHECK(!parse_mac("01:00:5e:00:00:01", mac)); // multicast
  CHECK(!parse_mac("", mac));
}

/* ═══════════════════════════════ addresses ═══════════════════════════════ */

TEST(test_parse_ipv4)
{
  uint32_t a;
  CHECK(parse_ipv4("192.168.4.1", &a));
  CHECK_EQ(a, ip("192.168.4.1"));
  CHECK(parse_ipv4("0.0.0.0", &a));
  CHECK(!parse_ipv4("256.1.1.1", &a));
  CHECK(!parse_ipv4("1.2.3", &a));
  CHECK(!parse_ipv4("1.2.3.4x", &a));
  CHECK(!parse_ipv4("", &a));
}

TEST(test_parse_cidr)
{
  char addr[16], mask[16];
  CHECK(parse_cidr("10.6.0.2/32", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK_STR(addr, "10.6.0.2");
  CHECK_STR(mask, "255.255.255.255");
  CHECK(parse_cidr("192.168.1.0/24", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK_STR(mask, "255.255.255.0");
  CHECK(parse_cidr("10.0.0.0/8", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK_STR(mask, "255.0.0.0");
  CHECK(parse_cidr("0.0.0.0/0", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK_STR(mask, "0.0.0.0");
  CHECK(parse_cidr("10.1.2.3", addr, sizeof(addr), mask, sizeof(mask))); // no prefix = /32
  CHECK_STR(mask, "255.255.255.255");
  CHECK(!parse_cidr("10.0.0.0/33", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK(!parse_cidr("10.0.0.0/", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK(!parse_cidr("10.0.0/24", addr, sizeof(addr), mask, sizeof(mask)));
  CHECK(!parse_cidr("/24", addr, sizeof(addr), mask, sizeof(mask)));
}

TEST(test_parse_split_networks)
{
  uint32_t nets[8], masks[8];
  CHECK_EQ(parse_split_networks("192.168.1.0/24, 10.0.0.0/8", nets, masks, 8), 2);
  CHECK_EQ(nets[0], ip("192.168.1.0"));
  CHECK_EQ(masks[0], ip("255.255.255.0"));
  CHECK_EQ(nets[1], ip("10.0.0.0"));
  CHECK_EQ(masks[1], ip("255.0.0.0"));

  CHECK_EQ(parse_split_networks("192.168.1.77/24", nets, masks, 8), 1);
  CHECK_EQ(nets[0], ip("192.168.1.0")); // host bits cleared

  CHECK_EQ(parse_split_networks("10.1.2.3;172.16.0.0/12", nets, masks, 8), 2);
  CHECK_EQ(masks[0], ip("255.255.255.255"));

  CHECK_EQ(parse_split_networks("", nets, masks, 8), 0);
  CHECK_EQ(parse_split_networks(" , ", nets, masks, 8), 0);
  CHECK_EQ(parse_split_networks("192.168.1.0/33", nets, masks, 8), -1);
  CHECK_EQ(parse_split_networks("a,b", nets, masks, 8), -1);
  CHECK_EQ(parse_split_networks("1.0.0.0/8 2.0.0.0/8 3.0.0.0/8", nets, masks, 2), -1); // more than max
}

/* ═══════════════════════════════ DNS ═══════════════════════════════ */

static int build_query(uint8_t *buf, const char *name, uint16_t qtype, bool edns)
{
  const uint8_t header[12] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, (uint8_t)(edns ? 1 : 0)};
  memcpy(buf, header, sizeof(header));
  int pos = 12;
  const char *label = name;
  while (*label)
  {
    const char *dot = strchr(label, '.');
    int len = dot ? (int)(dot - label) : (int)strlen(label);
    buf[pos++] = (uint8_t)len;
    memcpy(buf + pos, label, len);
    pos += len;
    label += len + (dot ? 1 : 0);
  }
  buf[pos++] = 0;
  buf[pos++] = qtype >> 8;
  buf[pos++] = qtype & 0xFF;
  buf[pos++] = 0;
  buf[pos++] = 1; // class IN
  if (edns)
  {
    const uint8_t opt[11] = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
    memcpy(buf + pos, opt, sizeof(opt));
    pos += sizeof(opt);
  }
  return pos;
}

TEST(test_dns_parse_query)
{
  uint8_t buf[512];
  char name[128];
  uint16_t qtype = 0;
  int len = build_query(buf, "Captive.Apple.com", 1, true);
  int end = dns_parse_query(buf, len, name, sizeof(name), &qtype);
  CHECK_EQ(end, 12 + 19 + 4); // header + name (7+5+3 chars, 3 length bytes, root) + type/class
  CHECK_STR(name, "captive.apple.com"); // lower case
  CHECK_EQ(qtype, 1);

  len = build_query(buf, "example.org", 28, false);
  CHECK(dns_parse_query(buf, len, name, sizeof(name), &qtype) > 0);
  CHECK_EQ(qtype, 28);

  CHECK_EQ(dns_parse_query(buf, 20, name, sizeof(name), &qtype), -1); // truncated
  CHECK_EQ(dns_parse_query(buf, 8, name, sizeof(name), &qtype), -1);  // shorter than a header

  len = build_query(buf, "example.org", 1, false);
  buf[2] |= 0x80; // a response, not a query
  CHECK_EQ(dns_parse_query(buf, len, name, sizeof(name), &qtype), -1);

  len = build_query(buf, "example.org", 1, false);
  buf[5] = 2; // two questions
  CHECK_EQ(dns_parse_query(buf, len, name, sizeof(name), &qtype), -1);

  len = build_query(buf, "example.org", 1, false);
  buf[12] = 0xC0; // compression pointer in a question
  CHECK_EQ(dns_parse_query(buf, len, name, sizeof(name), &qtype), -1);
}

TEST(test_dns_build_answer)
{
  uint8_t buf[512];
  char name[128];
  uint16_t qtype;
  int len = build_query(buf, "connectivitycheck.gstatic.com", 1, true);
  int end = dns_parse_query(buf, len, name, sizeof(name), &qtype);
  uint32_t addr = ip("192.168.4.1");
  int answer_len = dns_build_answer(buf, end, &addr, 0);
  CHECK_EQ(answer_len, end + DNS_ANSWER_LEN);
  CHECK_EQ(buf[0], 0x12); // ID kept
  CHECK_EQ(buf[1], 0x34);
  CHECK(buf[2] & 0x80);   // response
  CHECK(buf[2] & 0x01);   // RD kept
  CHECK_EQ(buf[3], 0x80); // RA, NOERROR
  CHECK_EQ(buf[7], 1);    // one answer
  CHECK_EQ(buf[11], 0);   // EDNS record dropped
  CHECK_EQ(buf[end + 9], 0); // TTL 0
  CHECK_EQ(memcmp(&buf[end + 12], &addr, 4), 0);

  len = build_query(buf, "captive.apple.com", 28, false);
  end = dns_parse_query(buf, len, name, sizeof(name), &qtype);
  CHECK_EQ(dns_build_answer(buf, end, NULL, 0), end); // AAAA: empty answer
  CHECK_EQ(buf[7], 0);
}

TEST(test_portal_probe_hosts)
{
  CHECK(is_portal_probe_host("connectivitycheck.gstatic.com"));
  CHECK(is_portal_probe_host("captive.apple.com"));
  CHECK(is_portal_probe_host("www.msftconnecttest.com"));
  CHECK(!is_portal_probe_host("www.google.com"));
  CHECK(!is_portal_probe_host("apple.com"));
  CHECK(!is_portal_probe_host(""));
}

/* ═══════════════════════════════ TCP MSS clamping ═══════════════════════════════ */

/* Full TCP checksum over pseudo header + segment (0 when the stored checksum is right) */
static uint16_t tcp_checksum(const uint8_t *packet, size_t len)
{
  size_t ip_hlen = (packet[0] & 0x0F) * 4;
  size_t tcp_len = len - ip_hlen;
  uint32_t sum = 0;
  for (int i = 12; i < 20; i += 2) // source and destination address
    sum += (packet[i] << 8) | packet[i + 1];
  sum += 6 + tcp_len;
  for (size_t i = 0; i < tcp_len; i += 2)
    sum += (packet[ip_hlen + i] << 8) | (i + 1 < tcp_len ? packet[ip_hlen + i + 1] : 0);
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

static void set_tcp_checksum(uint8_t *packet, size_t len)
{
  size_t ip_hlen = (packet[0] & 0x0F) * 4;
  packet[ip_hlen + 16] = 0;
  packet[ip_hlen + 17] = 0;
  uint16_t sum = tcp_checksum(packet, len);
  packet[ip_hlen + 16] = sum >> 8;
  packet[ip_hlen + 17] = sum & 0xFF;
}

/* IPv4 + TCP SYN with the given options (padded to 4 bytes) */
static size_t build_syn(uint8_t *packet, const uint8_t *options, size_t options_len, uint8_t flags)
{
  memset(packet, 0, 80);
  size_t tcp_hlen = 20 + ((options_len + 3) & ~(size_t)3);
  size_t len = 20 + tcp_hlen;
  packet[0] = 0x45;
  packet[3] = (uint8_t)len;
  packet[8] = 64;
  packet[9] = 6; // TCP
  const uint8_t addrs[8] = {192, 168, 4, 2, 93, 184, 216, 34};
  memcpy(packet + 12, addrs, 8);
  uint8_t *tcp = packet + 20;
  tcp[0] = 0xC0;
  tcp[1] = 0x01;
  tcp[2] = 0x01;
  tcp[3] = 0xBB;
  tcp[12] = (uint8_t)((tcp_hlen / 4) << 4);
  tcp[13] = flags;
  memcpy(tcp + 20, options, options_len);
  set_tcp_checksum(packet, len);
  return len;
}

static int mss_of(const uint8_t *packet, size_t offset)
{
  return (packet[20 + offset] << 8) | packet[20 + offset + 1];
}

TEST(test_clamp_tcp_mss)
{
  uint8_t packet[80];
  const uint8_t mss_first[] = {2, 4, 0x05, 0xB4, 1, 3, 3, 7}; // MSS 1460, NOP, window scale
  size_t len = build_syn(packet, mss_first, sizeof(mss_first), 0x02);
  CHECK_EQ(tcp_checksum(packet, len), 0);
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 22), 1380);
  CHECK_EQ(tcp_checksum(packet, len), 0); // incremental checksum update is right

  // MSS value at an odd offset (after one NOP) spans two checksum words
  const uint8_t mss_odd[] = {1, 2, 4, 0x05, 0xB4, 0, 0, 0};
  len = build_syn(packet, mss_odd, sizeof(mss_odd), 0x12); // SYN-ACK
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 23), 1380);
  CHECK_EQ(tcp_checksum(packet, len), 0);

  // Already small enough: untouched
  const uint8_t mss_small[] = {2, 4, 0x04, 0x00};
  len = build_syn(packet, mss_small, sizeof(mss_small), 0x02);
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 22), 1024);

  // Not a SYN: untouched
  len = build_syn(packet, mss_first, sizeof(mss_first), 0x10);
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 22), 1460);

  // Malformed option length: no crash, untouched
  const uint8_t bad[] = {2, 40, 0x05, 0xB4};
  len = build_syn(packet, bad, sizeof(bad), 0x02);
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 22), 1460);

  // Fragment: untouched
  len = build_syn(packet, mss_first, sizeof(mss_first), 0x02);
  packet[6] = 0x20; // MF
  clamp_tcp_mss(packet, len, 1380);
  CHECK_EQ(mss_of(packet, 22), 1460);

  // Truncated buffer: no read past the end
  clamp_tcp_mss(packet, 30, 1380);
}

/* ═══════════════════════════════ saved networks ═══════════════════════════════ */

TEST(test_remember_network)
{
  char s[5][32] = {{0}}, p[5][64] = {{0}};
  char *ssids[5] = {s[0], s[1], s[2], s[3], s[4]};
  char *passwords[5] = {p[0], p[1], p[2], p[3], p[4]};

  CHECK_EQ(remember_network(ssids, passwords, 5, 32, 64, "Home", "homepass"), 0);
  CHECK_STR(s[0], "Home");
  CHECK_STR(p[0], "homepass");

  // New network becomes the main one, Home moves to the first free slot
  CHECK_EQ(remember_network(ssids, passwords, 5, 32, 64, "Hotel", ""), 0);
  CHECK_STR(s[0], "Hotel");
  CHECK_STR(s[1], "Home");
  CHECK_STR(p[1], "homepass");

  // Known network keeps its slot; NULL keeps the password, a new one replaces it
  CHECK_EQ(remember_network(ssids, passwords, 5, 32, 64, "Home", NULL), 1);
  CHECK_STR(p[1], "homepass");
  CHECK_EQ(remember_network(ssids, passwords, 5, 32, 64, "Home", "newpass1"), 1);
  CHECK_STR(p[1], "newpass1");

  // All slots taken: the last one is dropped
  remember_network(ssids, passwords, 5, 32, 64, "C", "c");
  remember_network(ssids, passwords, 5, 32, 64, "D", "d");
  remember_network(ssids, passwords, 5, 32, 64, "E", "e");
  CHECK_STR(s[0], "E");
  CHECK_EQ(remember_network(ssids, passwords, 5, 32, 64, "F", "f"), 0);
  CHECK_STR(s[0], "F");
  CHECK_STR(s[4], "E"); // old main replaced the last slot
  int homes = 0;
  for (int i = 0; i < 5; i++)
    homes += strcmp(s[i], "Home") == 0;
  CHECK_EQ(homes, 1);
}

TEST(test_pick_best_network)
{
  const char *saved[5] = {"Home", "", "Hotel", "Phone", ""};
  const char *scan[4] = {"Neighbour", "Hotel", "Phone", "Home"}; // strongest first
  CHECK_EQ(pick_best_network(scan, 4, saved, 5), 2);
  const char *scan2[2] = {"Cafe", "Phone"};
  CHECK_EQ(pick_best_network(scan2, 2, saved, 5), 3);
  const char *scan3[2] = {"Cafe", ""}; // empty names never match empty slots
  CHECK_EQ(pick_best_network(scan3, 2, saved, 5), -1);
  CHECK_EQ(pick_best_network(scan, 0, saved, 5), -1);
}

/* ═══════════════════════════════ keyboard ═══════════════════════════════ */

TEST(test_keyboard_map)
{
  // Keys used as shortcuts (numbers from the M5Cardputer ADV layout)
  CHECK_EQ(keyboard_key_code(34, false, false), 'v');
  CHECK_EQ(keyboard_key_code(34, true, false), 'V');
  CHECK_EQ(keyboard_key_code(16, false, false), 'e');
  CHECK_EQ(keyboard_key_code(52, false, false), 'p');

  // Every key of the 4x14 layout has exactly one key number
  int seen[4][14] = {{0}};
  int count = 0;
  for (int k = 0; k <= 80; k++)
  {
    int row, column;
    if (keyboard_key_position((uint8_t)k, &row, &column))
    {
      CHECK(row >= 0 && row < 4 && column >= 0 && column < 14);
      seen[row][column]++;
      count++;
    }
  }
  CHECK_EQ(count, 56);
  for (int r = 0; r < 4; r++)
    for (int c = 0; c < 14; c++)
      CHECK_EQ(seen[r][c], 1);

  // Find keys by position for the rest of the checks
  uint8_t number[4][14] = {{0}};
  for (int k = 1; k <= 70; k++)
  {
    int row, column;
    if (keyboard_key_position((uint8_t)k, &row, &column))
      number[row][column] = (uint8_t)k;
  }
  CHECK_EQ(keyboard_key_code(number[0][13], false, false), KC_BACKSPACE);
  CHECK_EQ(keyboard_key_code(number[2][13], false, false), KC_ENTER);
  CHECK_EQ(keyboard_key_code(number[3][13], false, false), ' ');
  CHECK_EQ(keyboard_key_code(number[2][1], false, false), KC_SHIFT);
  CHECK_EQ(keyboard_key_code(number[2][0], false, false), KC_FN);
  CHECK_EQ(keyboard_key_code(number[0][1], true, false), '!');
  CHECK_EQ(keyboard_key_code(number[2][11], false, true), KC_UP);   // fn + ;
  CHECK_EQ(keyboard_key_code(number[3][11], false, true), KC_DOWN); // fn + .
  CHECK_EQ(keyboard_key_code(number[0][0], false, true), KC_ESC);   // fn + `
  CHECK_EQ(keyboard_key_code(number[2][11], false, false), ';');
  CHECK_EQ(keyboard_key_code(0, false, false), KC_NONE);
  CHECK_EQ(keyboard_key_code(9, false, false), KC_NONE); // matrix column 8 is not wired
}

/* ═══════════════════════════════ WiFi menu ═══════════════════════════════ */

static wifi_menu_t menu_with(int networks)
{
  wifi_menu_t menu;
  CHECK_EQ(wifi_menu_open(&menu), MENU_ACT_SCAN);
  CHECK_EQ(menu.screen, MENU_SCANNING);
  char name[16];
  for (int i = 0; i < networks; i++)
  {
    snprintf(name, sizeof(name), "net%d", i);
    wifi_menu_add_network(&menu, name, -40 - i, i % 2 == 1, i == 3);
  }
  wifi_menu_scan_done(&menu);
  return menu;
}

TEST(test_menu_list)
{
  wifi_menu_t menu;
  wifi_menu_open(&menu);
  CHECK(wifi_menu_add_network(&menu, "Hotel", -50, false, false));
  CHECK(!wifi_menu_add_network(&menu, "Hotel", -70, false, false)); // second access point
  CHECK(!wifi_menu_add_network(&menu, "", -30, true, false));       // hidden
  wifi_menu_scan_done(&menu);
  CHECK_EQ(menu.count, 1);
  CHECK_EQ(menu.screen, MENU_LIST);

  menu = menu_with(12);
  CHECK_EQ(menu.count, 12);
  CHECK_EQ(wifi_menu_key(&menu, KC_UP), MENU_ACT_REDRAW); // wraps to the last one
  CHECK_EQ(menu.selected, 11);
  CHECK_EQ(menu.scroll, 11 - MENU_VISIBLE_ROWS + 1);
  CHECK_EQ(wifi_menu_key(&menu, '.'), MENU_ACT_REDRAW); // plain . works as down in the list
  CHECK_EQ(menu.selected, 0);
  CHECK_EQ(menu.scroll, 0);
  for (int i = 0; i < MENU_VISIBLE_ROWS; i++)
    wifi_menu_key(&menu, KC_DOWN);
  CHECK_EQ(menu.selected, MENU_VISIBLE_ROWS);
  CHECK_EQ(menu.scroll, 1); // selection stays visible
  CHECK_EQ(wifi_menu_key(&menu, 'x'), MENU_ACT_NONE);
  CHECK_EQ(wifi_menu_key(&menu, ';'), MENU_ACT_REDRAW); // plain ; works as up
  CHECK_EQ(menu.selected, MENU_VISIBLE_ROWS - 1);
  CHECK_EQ(wifi_menu_key(&menu, 'r'), MENU_ACT_SCAN); // rescan
  CHECK_EQ(menu.screen, MENU_SCANNING);
  CHECK_EQ(menu.count, 0);

  wifi_menu_t empty = menu_with(0);
  CHECK_EQ(wifi_menu_key(&empty, KC_DOWN), MENU_ACT_NONE);
  CHECK_EQ(wifi_menu_key(&empty, KC_ENTER), MENU_ACT_NONE);
  CHECK(wifi_menu_selected(&empty) == NULL);
  CHECK_EQ(wifi_menu_key(&empty, KC_ESC), MENU_ACT_CLOSE);
  CHECK_EQ(empty.screen, MENU_CLOSED);

  // Left arrow (plain , in the list) goes back, also while scanning
  wifi_menu_t list = menu_with(3);
  CHECK_EQ(wifi_menu_key(&list, ','), MENU_ACT_CLOSE);
  wifi_menu_open(&list);
  CHECK_EQ(wifi_menu_key(&list, 'a'), MENU_ACT_NONE);
  CHECK_EQ(wifi_menu_key(&list, KC_LEFT), MENU_ACT_CLOSE);
}

TEST(test_menu_connect)
{
  // Open network: connect right away without a password
  wifi_menu_t menu = menu_with(4); // net0 open, net1 secured, net2 open, net3 secured + saved
  CHECK_EQ(wifi_menu_key(&menu, KC_ENTER), MENU_ACT_CONNECT);
  CHECK_STR(wifi_menu_selected(&menu)->ssid, "net0");
  CHECK(menu.password_entered);
  CHECK_STR(menu.password, "");

  // Saved secured network: connect with the saved password
  menu = menu_with(4);
  for (int i = 0; i < 3; i++)
    wifi_menu_key(&menu, KC_DOWN);
  CHECK_EQ(wifi_menu_key(&menu, KC_ENTER), MENU_ACT_CONNECT);
  CHECK_STR(wifi_menu_selected(&menu)->ssid, "net3");
  CHECK(!menu.password_entered);

  // ... or type a new one with P
  menu = menu_with(4);
  for (int i = 0; i < 3; i++)
    wifi_menu_key(&menu, KC_DOWN);
  CHECK_EQ(wifi_menu_key(&menu, 'p'), MENU_ACT_REDRAW);
  CHECK_EQ(menu.screen, MENU_PASSWORD);

  // Right arrow (plain /) joins like Enter
  menu = menu_with(4);
  CHECK_EQ(wifi_menu_key(&menu, '/'), MENU_ACT_CONNECT);
  CHECK_STR(wifi_menu_selected(&menu)->ssid, "net0");

  // Secured network: password screen
  menu = menu_with(4);
  wifi_menu_key(&menu, KC_DOWN);
  CHECK_EQ(wifi_menu_key(&menu, KC_ENTER), MENU_ACT_REDRAW);
  CHECK_EQ(menu.screen, MENU_PASSWORD);
  const char *typed = "Pa ss;.1"; // , / ; . are text in the password
  for (const char *c = typed; *c; c++)
    CHECK_EQ(wifi_menu_key(&menu, (uint8_t)*c), MENU_ACT_REDRAW); // ; and . are text here
  CHECK_STR(menu.password, "Pa ss;.1");
  CHECK_EQ(wifi_menu_key(&menu, KC_BACKSPACE), MENU_ACT_REDRAW);
  CHECK_STR(menu.password, "Pa ss;.");
  CHECK_EQ(wifi_menu_key(&menu, KC_ENTER), MENU_ACT_NONE); // 7 characters: too short
  CHECK_EQ(menu.screen, MENU_PASSWORD);
  CHECK_EQ(wifi_menu_key(&menu, KC_UP), MENU_ACT_NONE);    // arrows are ignored
  wifi_menu_key(&menu, '9');
  CHECK_EQ(wifi_menu_key(&menu, KC_ENTER), MENU_ACT_CONNECT);
  CHECK_STR(menu.password, "Pa ss;.9");
  CHECK(menu.password_entered);
  CHECK_EQ(menu.screen, MENU_CLOSED);

  // Esc or fn+left goes back to the list, Esc again closes
  menu = menu_with(4);
  wifi_menu_key(&menu, KC_DOWN);
  wifi_menu_key(&menu, KC_ENTER);
  CHECK_EQ(wifi_menu_key(&menu, ','), MENU_ACT_REDRAW); // typed
  CHECK_STR(menu.password, ",");
  CHECK_EQ(wifi_menu_key(&menu, KC_LEFT), MENU_ACT_REDRAW);
  CHECK_EQ(menu.screen, MENU_LIST);
  wifi_menu_key(&menu, KC_ENTER);
  CHECK_EQ(wifi_menu_key(&menu, KC_ESC), MENU_ACT_REDRAW);
  CHECK_EQ(menu.screen, MENU_LIST);
  CHECK_EQ(wifi_menu_key(&menu, KC_ESC), MENU_ACT_CLOSE);

  // Password length limit and backspace on an empty password
  menu = menu_with(2);
  wifi_menu_key(&menu, KC_DOWN);
  wifi_menu_key(&menu, KC_ENTER);
  CHECK_EQ(wifi_menu_key(&menu, KC_BACKSPACE), MENU_ACT_NONE);
  for (int i = 0; i < 70; i++)
    wifi_menu_key(&menu, 'a');
  CHECK_EQ(menu.password_len, MENU_PASSWORD_MAX);
  CHECK_EQ((int)strlen(menu.password), MENU_PASSWORD_MAX);
}

/* ═══════════════════════════════ security ═══════════════════════════════ */

TEST(test_validate_wpa_password)
{
  CHECK(validate_wpa_password("1234567") != NULL); // 7
  CHECK(validate_wpa_password("12345678") == NULL);
  CHECK(validate_wpa_password("") != NULL);
  char text[80];
  memset(text, 'a', sizeof(text));
  text[63] = '\0';
  CHECK(validate_wpa_password(text) == NULL); // 63
  text[63] = 'a';
  text[64] = '\0';
  CHECK(validate_wpa_password(text) == NULL); // 64 hex digits ('a')
  text[10] = 'g';
  CHECK(validate_wpa_password(text) != NULL); // 64 characters, not hex
  text[64] = 'a';
  text[65] = '\0';
  CHECK(validate_wpa_password(text) != NULL); // 65
  CHECK(validate_wpa_password("pass word 1!") == NULL);
  CHECK(validate_wpa_password("hasło12345") != NULL); // non-ASCII
  CHECK(validate_wpa_password("tab\there1") != NULL);
}

TEST(test_login_limiter)
{
  login_limiter_t limiter = {};
  uint32_t a = ip("192.168.4.2"), b = ip("192.168.4.3");
  uint32_t now = 1000, wait = 0;

  for (int i = 0; i < LOGIN_MAX_FAILURES - 1; i++)
  {
    CHECK(login_allowed(&limiter, a, now, &wait));
    CHECK(!login_failed(&limiter, a, now));
  }
  CHECK(login_allowed(&limiter, a, now, &wait));
  CHECK(login_failed(&limiter, a, now)); // 5th failure locks
  CHECK(!login_allowed(&limiter, a, now + 1000, &wait));
  CHECK_EQ(wait, LOGIN_LOCK_MS - 1000);
  CHECK_EQ(login_locked_count(&limiter, now + 1000), 1);
  CHECK(login_allowed(&limiter, b, now + 1000, &wait)); // other addresses are not affected

  // Lock over: allowed again with a fresh count
  CHECK(login_allowed(&limiter, a, now + LOGIN_LOCK_MS, &wait));
  CHECK_EQ(login_locked_count(&limiter, now + LOGIN_LOCK_MS), 0);
  CHECK(!login_failed(&limiter, a, now + LOGIN_LOCK_MS));

  // Success forgets the failures
  for (int i = 0; i < LOGIN_MAX_FAILURES - 1; i++)
    login_failed(&limiter, b, now);
  login_succeeded(&limiter, b);
  CHECK(!login_failed(&limiter, b, now)); // counts from 1 again
  CHECK(login_allowed(&limiter, b, now, &wait));

  // Full table: the address not seen for the longest time is replaced
  login_limiter_t full = {};
  for (uint32_t i = 0; i < LOGIN_LIMITER_ENTRIES; i++)
    login_failed(&full, 100 + i, 5000 + i);
  login_failed(&full, 999, 9000); // replaces address 100
  for (int i = 0; i < LOGIN_MAX_FAILURES - 1; i++)
    login_failed(&full, 101, 9100);
  CHECK(!login_allowed(&full, 101, 9200, NULL)); // 101 kept its first failure
  for (int i = 0; i < LOGIN_MAX_FAILURES - 1; i++)
    CHECK(!login_failed(&full, 100, 9300)); // 100 starts from scratch

  // Millisecond counter wrapping around during a lock
  login_limiter_t wrap = {};
  uint32_t late = 0xFFFFFFFFu - 1000;
  for (int i = 0; i < LOGIN_MAX_FAILURES; i++)
    login_failed(&wrap, a, late);
  CHECK(!login_allowed(&wrap, a, late + 5000, NULL)); // wrapped, still locked
  CHECK(login_allowed(&wrap, a, late + LOGIN_LOCK_MS + 1, NULL));
}

/* ═══════════════════════════════ WiFi QR code ═══════════════════════════════ */

TEST(test_wifi_qr_payload)
{
  char out[256];
  CHECK(wifi_qr_payload(out, sizeof(out), "Domek_Mobile", "secret123"));
  CHECK_STR(out, "WIFI:T:WPA;S:Domek_Mobile;P:secret123;;");
  CHECK(wifi_qr_payload(out, sizeof(out), "Open Cafe", ""));
  CHECK_STR(out, "WIFI:T:nopass;S:Open Cafe;;");
  CHECK(wifi_qr_payload(out, sizeof(out), "Open Cafe", NULL));
  CHECK_STR(out, "WIFI:T:nopass;S:Open Cafe;;");
  // Special characters are escaped
  CHECK(wifi_qr_payload(out, sizeof(out), "a;b,c", "p:w\\d\"x"));
  CHECK_STR(out, "WIFI:T:WPA;S:a\\;b\\,c;P:p\\:w\\\\d\\\"x;;");
  // Too small: false and an empty string, never a cut payload
  char small[20];
  CHECK(!wifi_qr_payload(small, sizeof(small), "Domek_Mobile", "secret123"));
  CHECK_STR(small, "");
  // Longest SSID and password with every character escaped fit the firmware's buffer
  char ssid[32], password[64];
  memset(ssid, ';', 31);
  ssid[31] = '\0';
  memset(password, ':', 63);
  password[63] = '\0';
  char big[256];
  CHECK(wifi_qr_payload(big, sizeof(big), ssid, password));
  CHECK_EQ(strlen(big), 13 + 62 + 1 + 2 + 126 + 2);
}

TEST(test_wifi_qr_code)
{
  // The firmware encodes with version <= 10, low error correction (boosted)
  uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
  uint8_t temp[qrcodegen_BUFFER_LEN_FOR_VERSION(10)];
  char payload[256];
  wifi_qr_payload(payload, sizeof(payload), "Domek_Mobile", "secret123");
  CHECK(qrcodegen_encodeText(payload, temp, qr, qrcodegen_Ecc_LOW, 1, 10, qrcodegen_Mask_AUTO, true));
  CHECK_EQ(qrcodegen_getSize(qr), 29); // version 3
  // Finder pattern corners are dark
  CHECK(qrcodegen_getModule(qr, 0, 0));
  CHECK(qrcodegen_getModule(qr, 28, 0));
  CHECK(qrcodegen_getModule(qr, 0, 28));

  // The longest possible payload still fits version 10
  char ssid[32], password[64], big[256];
  memset(ssid, ';', 31);
  ssid[31] = '\0';
  memset(password, ':', 63);
  password[63] = '\0';
  wifi_qr_payload(big, sizeof(big), ssid, password);
  CHECK(qrcodegen_encodeText(big, temp, qr, qrcodegen_Ecc_LOW, 1, 10, qrcodegen_Mask_AUTO, true));
  CHECK(qrcodegen_getSize(qr) <= 57);
}

/* ═══════════════════════════════ WireGuard import ═══════════════════════════════ */

#define PRIV "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
#define PEER "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
#define PSK "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

TEST(test_wg_import_full)
{
  // wg-quick / WireGuard app export with IPv6 next to IPv4, CRLF and comments
  const char *conf = "# phone\r\n"
                     "[Interface]\r\n"
                     "PrivateKey = " PRIV "\r\n"
                     "Address = 10.6.0.2/32, fd00::2/128\r\n"
                     "DNS = 1.1.1.1, 2606:4700::1111\r\n"
                     "ListenPort = 51820   ; ignored\r\n"
                     "\r\n"
                     "[Peer]\r\n"
                     "PublicKey = " PEER "\r\n"
                     "PresharedKey = " PSK "\r\n"
                     "AllowedIPs = 0.0.0.0/0, ::/0\r\n"
                     "Endpoint = vpn.example.com:443\r\n"
                     "PersistentKeepalive = 15\r\n";
  wg_import_t wg;
  char error[128] = "";
  CHECK(parse_wireguard_conf(conf, &wg, error, sizeof(error)));
  CHECK_STR(error, "");
  CHECK_STR(wg.private_key, PRIV);
  CHECK_STR(wg.address, "10.6.0.2/32");
  CHECK_STR(wg.dns, "1.1.1.1");
  CHECK_STR(wg.peer_public_key, PEER);
  CHECK_STR(wg.preshared_key, PSK);
  CHECK_STR(wg.endpoint_host, "vpn.example.com");
  CHECK_EQ(wg.endpoint_port, 443);
  CHECK_EQ(wg.keepalive, 15);
  CHECK(wg.full_tunnel);
  CHECK_STR(wg.split, "");
  CHECK(strstr(wg.warnings, "IPv6 entries ignored") != NULL);
}

TEST(test_wg_import_split)
{
  // MikroTik style: lower case keys, no keepalive, endpoint without port, /1 halves elsewhere
  const char *conf = "[interface]\n"
                     "privatekey=" PRIV "\n"
                     "address=192.168.30.2\n"
                     "[peer]\n"
                     "publickey=" PEER "\n"
                     "allowedips=192.168.1.0/24, 10.0.0.0/8\n"
                     "allowedips=172.16.0.0/12\n"
                     "endpoint=80.68.225.149\n";
  wg_import_t wg;
  char error[128] = "";
  CHECK(parse_wireguard_conf(conf, &wg, error, sizeof(error)));
  CHECK_STR(wg.address, "192.168.30.2/32");
  CHECK_STR(wg.dns, "");
  CHECK_STR(wg.preshared_key, "");
  CHECK_STR(wg.endpoint_host, "80.68.225.149");
  CHECK_EQ(wg.endpoint_port, 51820);
  CHECK_EQ(wg.keepalive, 25); // set for NAT
  CHECK(strstr(wg.warnings, "PersistentKeepalive") != NULL);
  CHECK(!wg.full_tunnel);
  CHECK_STR(wg.split, "192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/12");

  // 0.0.0.0/1 + 128.0.0.0/1 is all of IPv4
  const char *halves = "[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/24\n"
                       "[Peer]\nPublicKey=" PEER "\nEndpoint=1.2.3.4:51820\nAllowedIPs=0.0.0.0/1,128.0.0.0/1\n";
  CHECK(parse_wireguard_conf(halves, &wg, error, sizeof(error)));
  CHECK(wg.full_tunnel);
}

TEST(test_wg_import_errors)
{
  wg_import_t wg;
  char error[128];
  CHECK(!parse_wireguard_conf("hello", &wg, error, sizeof(error)));
  CHECK(strstr(error, "[Interface]") != NULL);
  CHECK(!parse_wireguard_conf("[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/32\n", &wg, error, sizeof(error)));
  CHECK(strstr(error, "[Peer]") != NULL);

  const char *bad_key = "[Interface]\nPrivateKey=abc\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" PEER
                        "\nEndpoint=1.2.3.4:1\nAllowedIPs=0.0.0.0/0\n";
  CHECK(!parse_wireguard_conf(bad_key, &wg, error, sizeof(error)));
  CHECK(strstr(error, "PrivateKey") != NULL);

  // A too long key must not be cut into a valid looking one
  const char *long_key = "[Interface]\nPrivateKey=" PRIV "AAAA\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" PEER
                         "\nEndpoint=1.2.3.4:1\nAllowedIPs=0.0.0.0/0\n";
  CHECK(!parse_wireguard_conf(long_key, &wg, error, sizeof(error)));

  const char *v6_endpoint = "[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" PEER
                            "\nEndpoint=[2001:db8::1]:51820\nAllowedIPs=0.0.0.0/0\n";
  CHECK(!parse_wireguard_conf(v6_endpoint, &wg, error, sizeof(error)));
  CHECK(strstr(error, "IPv6") != NULL);

  const char *bad_port = "[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" PEER
                         "\nEndpoint=host:99999\nAllowedIPs=0.0.0.0/0\n";
  CHECK(!parse_wireguard_conf(bad_port, &wg, error, sizeof(error)));

  const char *v6_only = "[Interface]\nPrivateKey=" PRIV "\nAddress=fd00::2/128\n[Peer]\nPublicKey=" PEER
                        "\nEndpoint=1.2.3.4\nAllowedIPs=::/0\n";
  CHECK(!parse_wireguard_conf(v6_only, &wg, error, sizeof(error)));
  CHECK(strstr(error, "IPv4 Address") != NULL);

  const char *too_many = "[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" PEER
                         "\nEndpoint=1.2.3.4\nAllowedIPs=1.0.0.0/8,2.0.0.0/8,3.0.0.0/8,4.0.0.0/8,5.0.0.0/8,"
                         "6.0.0.0/8,7.0.0.0/8,8.0.0.0/8,9.0.0.0/8\n";
  CHECK(!parse_wireguard_conf(too_many, &wg, error, sizeof(error)));
  CHECK(strstr(error, "8") != NULL);

  // Two peers: the first one is used, with a warning
  const char *two = "[Interface]\nPrivateKey=" PRIV "\nAddress=10.0.0.2/32\n"
                    "[Peer]\nPublicKey=" PEER "\nEndpoint=first.example\nAllowedIPs=10.1.0.0/16\n"
                    "[Peer]\nPublicKey=" PSK "\nEndpoint=second.example\nAllowedIPs=10.2.0.0/16\n";
  CHECK(parse_wireguard_conf(two, &wg, error, sizeof(error)));
  CHECK_STR(wg.endpoint_host, "first.example");
  CHECK_STR(wg.split, "10.1.0.0/16");
  CHECK(strstr(wg.warnings, "first [Peer]") != NULL);
}

int main(void)
{
  RUN(test_url_decode);
  RUN(test_parse_query_param);
  RUN(test_parse_mac);
  RUN(test_parse_ipv4);
  RUN(test_parse_cidr);
  RUN(test_parse_split_networks);
  RUN(test_dns_parse_query);
  RUN(test_dns_build_answer);
  RUN(test_portal_probe_hosts);
  RUN(test_clamp_tcp_mss);
  RUN(test_remember_network);
  RUN(test_pick_best_network);
  RUN(test_keyboard_map);
  RUN(test_menu_list);
  RUN(test_menu_connect);
  RUN(test_validate_wpa_password);
  RUN(test_login_limiter);
  RUN(test_wifi_qr_payload);
  RUN(test_wifi_qr_code);
  RUN(test_wg_import_full);
  RUN(test_wg_import_split);
  RUN(test_wg_import_errors);
  run_tracker_tests();
  run_roomscan_tests();
  printf("\n%d checks, %d failed\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
