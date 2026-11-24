/*
 * Network and parsing helpers without ESP-IDF dependencies - used by the
 * firmware and by the host unit tests (test/host).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* "a.b.c.d" -> address in network byte order */
bool parse_ipv4(const char *text, uint32_t *addr);

/* "a.b.c.d/prefix" (no prefix = /32) -> address and netmask strings */
bool parse_cidr(const char *cidr, char *ip_out, size_t ip_len, char *mask_out, size_t mask_len);

/* "192.168.1.0/24, 10.0.0.0/8" -> networks/masks (network byte order); count or -1 */
int parse_split_networks(const char *list, uint32_t *nets, uint32_t *masks, int max_count);

/* "AA:BB:CC:DD:EE:FF" (also '-' or no separators), unicast only */
bool parse_mac(const char *text, uint8_t mac[6]);

/* URL decoding (%XX and '+') of form data */
void url_decode(char *dst, const char *src);

/* Value of field_name in URL encoded form data, decoded; false if absent */
bool parse_query_param(const char *query, const char *field_name, char *output, size_t output_len);

/* DNS */
#define DNS_HEADER_LEN 12
#define DNS_ANSWER_LEN 16 // A record with a name pointer

/* Standard query with one question: lower case name and type; end of the question or -1 */
int dns_parse_query(const uint8_t *buf, int len, char *name, size_t name_len, uint16_t *qtype);

/* Query -> answer in place; with addr (network byte order) an A record follows (needs DNS_ANSWER_LEN spare bytes) */
int dns_build_answer(uint8_t *buf, int question_end, const uint32_t *addr, uint32_t ttl);

/* Host names operating systems use for their captive portal checks */
bool is_portal_probe_host(const char *name);

/* TCP MSS clamping */
uint16_t checksum_replace_word(uint16_t checksum, uint16_t old_word, uint16_t new_word);
void clamp_tcp_mss(uint8_t *packet, size_t len, uint16_t max_mss);

/*
 * Saved uplink networks (parallel arrays of buffers). Stores ssid/password
 * and returns its slot: an already saved network keeps its slot (password
 * NULL keeps the saved one); a new network becomes slot 0 and the previous
 * main network moves to a free slot (the last one when all are taken).
 */
int remember_network(char *const ssids[], char *const passwords[], int count, size_t ssid_size, size_t password_size,
                     const char *ssid, const char *password);

/* Index of the strongest saved network in scan results sorted by RSSI, or -1 */
int pick_best_network(const char *const scan_ssids[], int scan_count, const char *const saved_ssids[], int saved_count);

/*
 * WPA2 passphrase: 8-63 printable ASCII characters, or exactly 64 hex
 * digits (the key itself). Returns NULL when valid, otherwise the reason.
 */
const char *validate_wpa_password(const char *password);

/*
 * Login limiter for the web panel: after LOGIN_MAX_FAILURES wrong
 * passwords from one address, that address is locked for
 * LOGIN_LOCK_MS. Addresses are IPv4 in any byte order; times in ms.
 */
#define LOGIN_LIMITER_ENTRIES 8
#define LOGIN_MAX_FAILURES 5
#define LOGIN_LOCK_MS 60000

typedef struct
{
  uint32_t addr;
  uint8_t failures;
  uint32_t locked_until; // 0 = not locked
  uint32_t last_seen;
  bool used;
} login_entry_t;

typedef struct
{
  login_entry_t entries[LOGIN_LIMITER_ENTRIES];
} login_limiter_t;

/* False while addr is locked; then *wait_ms (if not NULL) is the time left */
bool login_allowed(login_limiter_t *limiter, uint32_t addr, uint32_t now_ms, uint32_t *wait_ms);
/* A wrong password from addr; returns true when this locked it */
bool login_failed(login_limiter_t *limiter, uint32_t addr, uint32_t now_ms);
/* A correct password: forget the failures of addr */
void login_succeeded(login_limiter_t *limiter, uint32_t addr);
/* Addresses locked at now_ms */
int login_locked_count(const login_limiter_t *limiter, uint32_t now_ms);

/*
 * Text of a WiFi QR code (phones join by scanning it):
 * WIFI:T:WPA;S:<ssid>;P:<password>;;  or  WIFI:T:nopass;S:<ssid>;;
 * \ ; , : and " are escaped with a backslash. False if out is too small.
 */
bool wifi_qr_payload(char *out, size_t out_len, const char *ssid, const char *password);

/*
 * WireGuard configuration file (wg-quick / MikroTik / app export) for the
 * web panel's import: the [Interface] and the first [Peer]. IPv4 only -
 * IPv6 addresses and networks are skipped with a warning.
 */
typedef struct
{
  char private_key[45];
  char address[20];      // first IPv4 address, "a.b.c.d/nn"
  char dns[16];          // first IPv4 DNS server, empty if none
  char peer_public_key[45];
  char preshared_key[45]; // empty if none
  char endpoint_host[64];
  uint16_t endpoint_port;
  uint16_t keepalive;
  bool full_tunnel;      // AllowedIPs covers all of IPv4
  char split[160];       // otherwise the IPv4 networks of AllowedIPs, "a.b.c.d/nn, ..."
  char warnings[160];    // things that were skipped, empty if none
} wg_import_t;

/* Parse a WireGuard configuration file; false with the reason in error */
bool parse_wireguard_conf(const char *text, wg_import_t *out, char *error, size_t error_len);
