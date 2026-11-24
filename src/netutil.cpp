/*
 * Network and parsing helpers without ESP-IDF dependencies - used by the
 * firmware and by the host unit tests (test/host).
 */

#include "netutil.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool parse_ipv4(const char *text, uint32_t *addr)
{
  unsigned parts[4];
  int consumed = 0;
  if (sscanf(text, "%3u.%3u.%3u.%3u%n", &parts[0], &parts[1], &parts[2], &parts[3], &consumed) != 4 ||
      text[consumed] != '\0')
    return false;
  uint8_t bytes[4];
  for (int i = 0; i < 4; i++)
  {
    if (parts[i] > 255)
      return false;
    bytes[i] = (uint8_t)parts[i];
  }
  memcpy(addr, bytes, 4); // network byte order, like lwIP
  return true;
}

/**
 * URL decode helper function
 */
void url_decode(char *dst, const char *src)
{
  char a, b;
  while (*src)
  {
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b)))
    {
      if (a >= 'a')
        a -= 'a' - 'A';
      if (a >= 'A')
        a -= ('A' - 10);
      else
        a -= '0';
      if (b >= 'a')
        b -= 'a' - 'A';
      if (b >= 'A')
        b -= ('A' - 10);
      else
        b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
    }
    else if (*src == '+')
    {
      *dst++ = ' ';
      src++;
    }
    else
    {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

/**
 * Parse "AA:BB:CC:DD:EE:FF" (also with '-' or without separators). Only
 * unicast addresses (lowest bit of the first byte clear) are accepted.
 */
bool parse_mac(const char *text, uint8_t mac[6])
{
  int digits = 0;
  uint8_t value[6] = {0};
  for (const char *c = text; *c; c++)
  {
    if (*c == ':' || *c == '-' || *c == ' ')
      continue;
    if (!isxdigit((unsigned char)*c) || digits >= 12)
      return false;
    int nibble = isdigit((unsigned char)*c) ? *c - '0' : (tolower((unsigned char)*c) - 'a' + 10);
    value[digits / 2] = (value[digits / 2] << 4) | nibble;
    digits++;
  }
  if (digits != 12 || (value[0] & 0x01))
    return false;
  memcpy(mac, value, 6);
  return true;
}

bool parse_query_param(const char *query, const char *field_name, char *output, size_t output_len)
{
  if (!query)
    return false;

  char search_key[64];
  snprintf(search_key, sizeof(search_key), "%s=", field_name);

  // Match only whole field names (at the start or right after '&')
  const char *start = query;
  while ((start = strstr(start, search_key)) != NULL)
  {
    if (start == query || start[-1] == '&')
      break;
    start++;
  }
  if (!start)
    return false;

  start += strlen(search_key);
  const char *end = strchr(start, '&');
  size_t len = end ? (end - start) : strlen(start);

  if (len >= output_len)
    len = output_len - 1;

  char temp[128];
  if (len >= sizeof(temp))
    len = sizeof(temp) - 1;

  strncpy(temp, start, len);
  temp[len] = '\0';

  url_decode(output, temp);
  return true;
}

/**
 * Parse "a.b.c.d/prefix" into separate address and netmask strings.
 * A missing prefix means /32.
 */
bool parse_cidr(const char *cidr, char *ip_out, size_t ip_len, char *mask_out, size_t mask_len)
{
  char ip[16];
  const char *slash = strchr(cidr, '/');
  size_t addr_len = slash ? (size_t)(slash - cidr) : strlen(cidr);
  if (addr_len == 0 || addr_len >= sizeof(ip))
    return false;
  memcpy(ip, cidr, addr_len);
  ip[addr_len] = '\0';

  uint32_t addr;
  if (!parse_ipv4(ip, &addr))
    return false;

  int prefix = 32;
  if (slash)
  {
    char *end;
    prefix = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' || prefix < 0 || prefix > 32)
      return false;
  }

  uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
  snprintf(ip_out, ip_len, "%s", ip);
  snprintf(mask_out, mask_len, "%u.%u.%u.%u",
           (unsigned)(mask >> 24) & 0xFF, (unsigned)(mask >> 16) & 0xFF,
           (unsigned)(mask >> 8) & 0xFF, (unsigned)mask & 0xFF);
  return true;
}

/**
 * Parse "a.b.c.d/nn, a.b.c.d/nn ..." (separated by commas, semicolons or
 * spaces) into network/mask pairs in network byte order. Returns the
 * number of networks, or -1 for a bad entry or more than max_count.
 */
int parse_split_networks(const char *list, uint32_t *nets, uint32_t *masks, int max_count)
{
  int count = 0;
  const char *p = list;
  while (*p)
  {
    while (*p == ' ' || *p == ',' || *p == ';')
      p++;
    if (!*p)
      break;
    char entry[24];
    size_t len = strcspn(p, " ,;");
    if (len >= sizeof(entry) || count >= max_count)
      return -1;
    memcpy(entry, p, len);
    entry[len] = '\0';
    p += len;

    char ip[16], mask[16];
    uint32_t a, m;
    if (!parse_cidr(entry, ip, sizeof(ip), mask, sizeof(mask)) || !parse_ipv4(ip, &a) || !parse_ipv4(mask, &m))
      return -1;
    nets[count] = a & m;
    masks[count] = m;
    count++;
  }
  return count;
}

/* Host names operating systems use to detect captive portals */
static const char *const PORTAL_PROBE_HOSTS[] = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.appleiphonecell.com",
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "network-test.debian.org",
    "connectivity-check.ubuntu.com",
    "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com",
};

/**
 * Parse a standard query (QR=0, OPCODE=0) with exactly one question.
 * Writes the lower case name and type; returns the length of the
 * question section end (offset) or -1.
 */
int dns_parse_query(const uint8_t *buf, int len, char *name, size_t name_len, uint16_t *qtype)
{
  if (len < DNS_HEADER_LEN || (buf[2] & 0x80) || (buf[2] & 0x78) || buf[4] != 0 || buf[5] != 1)
    return -1;

  int pos = DNS_HEADER_LEN;
  size_t out = 0;
  while (pos < len && buf[pos] != 0)
  {
    int label = buf[pos];
    if ((label & 0xC0) || pos + 1 + label > len)
      return -1;
    if (out > 0 && out < name_len - 1)
      name[out++] = '.';
    for (int i = 0; i < label; i++)
      if (out < name_len - 1)
        name[out++] = (char)tolower(buf[pos + 1 + i]);
    pos += label + 1;
  }
  name[out] = '\0';
  pos++; // zero length root label
  if (pos + 4 > len)
    return -1;
  *qtype = (buf[pos] << 8) | buf[pos + 1];
  return pos + 4;
}

/**
 * Turn the query in buf into an answer in place. With an address (network
 * byte order) an A
 * record follows the question (buf needs DNS_ANSWER_LEN spare bytes),
 * otherwise the answer is empty. Returns the answer length.
 */
int dns_build_answer(uint8_t *buf, int question_end, const uint32_t *addr, uint32_t ttl)
{
  buf[2] = 0x84 | (buf[2] & 0x01); // QR, AA, keep RD
  buf[3] = 0x80;                   // RA, NOERROR
  buf[6] = 0;
  buf[7] = addr ? 1 : 0;      // ANCOUNT
  memset(&buf[8], 0, 4);      // NSCOUNT, ARCOUNT - drops any EDNS record
  if (!addr)
    return question_end;

  const uint8_t record[12] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                              (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
                              0x00, 0x04};
  memcpy(&buf[question_end], record, sizeof(record));
  memcpy(&buf[question_end + 12], addr, 4);
  return question_end + DNS_ANSWER_LEN;
}

bool is_portal_probe_host(const char *name)
{
  for (size_t i = 0; i < sizeof(PORTAL_PROBE_HOSTS) / sizeof(PORTAL_PROBE_HOSTS[0]); i++)
    if (strcmp(name, PORTAL_PROBE_HOSTS[i]) == 0)
      return true;
  return false;
}

/**
 * Incremental Internet checksum update for one changed 16-bit word (RFC 1624)
 */
uint16_t checksum_replace_word(uint16_t checksum, uint16_t old_word, uint16_t new_word)
{
  uint32_t sum = (uint16_t)~checksum + (uint16_t)~old_word + new_word;
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

/**
 * Lower the MSS option of an IPv4 TCP SYN segment to max_mss, in place
 */
void clamp_tcp_mss(uint8_t *packet, size_t len, uint16_t max_mss)
{
  if (len < 20 || (packet[0] >> 4) != 4 || packet[9] != 6 /* TCP */)
    return;
  // Only unfragmented packets (MF flag and fragment offset zero)
  if ((packet[6] & 0x3F) != 0 || packet[7] != 0)
    return;
  size_t ip_hlen = (packet[0] & 0x0F) * 4;
  if (ip_hlen < 20 || len < ip_hlen + 20)
    return;

  uint8_t *tcp = packet + ip_hlen;
  size_t tcp_hlen = (tcp[12] >> 4) * 4;
  if (!(tcp[13] & 0x02) || tcp_hlen < 20 || len < ip_hlen + tcp_hlen)
    return; // not a SYN or truncated

  for (size_t i = 20; i < tcp_hlen;)
  {
    uint8_t kind = tcp[i];
    if (kind == 0) // end of option list
      break;
    if (kind == 1) // NOP
    {
      i++;
      continue;
    }
    if (i + 1 >= tcp_hlen || tcp[i + 1] < 2 || i + tcp[i + 1] > tcp_hlen)
      break; // malformed
    if (kind == 2 && tcp[i + 1] == 4) // MSS
    {
      uint16_t mss = (tcp[i + 2] << 8) | tcp[i + 3];
      if (mss <= max_mss)
        return;

      // The value may start at an odd offset and then spans two checksum words
      size_t first = (i + 2) & ~(size_t)1;
      size_t words = ((i + 2) & 1) ? 2 : 1;
      uint16_t old_words[2];
      for (size_t w = 0; w < words; w++)
        old_words[w] = (tcp[first + 2 * w] << 8) | tcp[first + 2 * w + 1];

      tcp[i + 2] = max_mss >> 8;
      tcp[i + 3] = max_mss & 0xFF;

      uint16_t checksum = (tcp[16] << 8) | tcp[17];
      for (size_t w = 0; w < words; w++)
        checksum = checksum_replace_word(checksum, old_words[w], (tcp[first + 2 * w] << 8) | tcp[first + 2 * w + 1]);
      tcp[16] = checksum >> 8;
      tcp[17] = checksum & 0xFF;
      return;
    }
    i += tcp[i + 1];
  }
}

/* ═══════════════════════════════════════════════════════════════════
 * Saved uplink networks
 * ═══════════════════════════════════════════════════════════════════ */

int remember_network(char *const ssids[], char *const passwords[], int count, size_t ssid_size, size_t password_size,
                     const char *ssid, const char *password)
{
  for (int i = 0; i < count; i++)
  {
    if (ssids[i][0] != '\0' && strcmp(ssids[i], ssid) == 0)
    {
      if (password)
        snprintf(passwords[i], password_size, "%s", password);
      return i;
    }
  }

  // New network: it becomes the main one, the old main one moves to a free slot
  if (ssids[0][0] != '\0')
  {
    int slot = count - 1; // all full: the last one is dropped
    for (int i = 1; i < count; i++)
      if (ssids[i][0] == '\0')
      {
        slot = i;
        break;
      }
    snprintf(ssids[slot], ssid_size, "%s", ssids[0]);
    snprintf(passwords[slot], password_size, "%s", passwords[0]);
  }
  snprintf(ssids[0], ssid_size, "%s", ssid);
  snprintf(passwords[0], password_size, "%s", password ? password : "");
  return 0;
}

int pick_best_network(const char *const scan_ssids[], int scan_count, const char *const saved_ssids[], int saved_count)
{
  // Scan results are sorted by signal strength: the first saved one is the strongest
  for (int r = 0; r < scan_count; r++)
    for (int i = 0; i < saved_count; i++)
      if (saved_ssids[i][0] != '\0' && strcmp(scan_ssids[r], saved_ssids[i]) == 0)
        return i;
  return -1;
}
