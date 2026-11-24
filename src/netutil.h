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
