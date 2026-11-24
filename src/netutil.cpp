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

/* ═══════════════════════════════════════════════════════════════════
 * Passwords and logins
 * ═══════════════════════════════════════════════════════════════════ */

const char *validate_wpa_password(const char *password)
{
  size_t len = strlen(password);
  if (len == 64)
  {
    for (size_t i = 0; i < len; i++)
      if (!isxdigit((unsigned char)password[i]))
        return "A 64 character password must be a hex key (0-9, a-f)";
    return NULL;
  }
  if (len < 8 || len > 63)
    return "The password needs 8-63 characters";
  for (size_t i = 0; i < len; i++)
    if ((unsigned char)password[i] < 0x20 || (unsigned char)password[i] > 0x7E)
      return "The password may only use plain ASCII characters (no accents or emoji)";
  return NULL;
}

/* Time comparisons survive the millisecond counter wrapping around */
static bool time_before(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

static login_entry_t *find_entry(login_limiter_t *limiter, uint32_t addr)
{
  for (int i = 0; i < LOGIN_LIMITER_ENTRIES; i++)
    if (limiter->entries[i].used && limiter->entries[i].addr == addr)
      return &limiter->entries[i];
  return NULL;
}

bool login_allowed(login_limiter_t *limiter, uint32_t addr, uint32_t now_ms, uint32_t *wait_ms)
{
  login_entry_t *entry = find_entry(limiter, addr);
  if (entry && entry->locked_until != 0)
  {
    if (time_before(now_ms, entry->locked_until))
    {
      if (wait_ms)
        *wait_ms = entry->locked_until - now_ms;
      return false;
    }
    // Lock over: a fresh start
    entry->locked_until = 0;
    entry->failures = 0;
  }
  return true;
}

bool login_failed(login_limiter_t *limiter, uint32_t addr, uint32_t now_ms)
{
  login_entry_t *entry = find_entry(limiter, addr);
  if (!entry)
  {
    // A free entry, else the one not seen for the longest time
    entry = &limiter->entries[0];
    for (int i = 0; i < LOGIN_LIMITER_ENTRIES; i++)
    {
      login_entry_t *candidate = &limiter->entries[i];
      if (!candidate->used)
      {
        entry = candidate;
        break;
      }
      if (time_before(candidate->last_seen, entry->last_seen))
        entry = candidate;
    }
    memset(entry, 0, sizeof(*entry));
    entry->used = true;
    entry->addr = addr;
  }
  entry->last_seen = now_ms;
  if (entry->failures < 255)
    entry->failures++;
  if (entry->failures >= LOGIN_MAX_FAILURES && entry->locked_until == 0)
  {
    entry->locked_until = now_ms + LOGIN_LOCK_MS;
    if (entry->locked_until == 0)
      entry->locked_until = 1; // 0 means "not locked"
    return true;
  }
  return false;
}

void login_succeeded(login_limiter_t *limiter, uint32_t addr)
{
  login_entry_t *entry = find_entry(limiter, addr);
  if (entry)
    memset(entry, 0, sizeof(*entry));
}

int login_locked_count(const login_limiter_t *limiter, uint32_t now_ms)
{
  int count = 0;
  for (int i = 0; i < LOGIN_LIMITER_ENTRIES; i++)
    if (limiter->entries[i].used && limiter->entries[i].locked_until != 0 &&
        time_before(now_ms, limiter->entries[i].locked_until))
      count++;
  return count;
}

/* ═══════════════════════════════════════════════════════════════════
 * WiFi QR code
 * ═══════════════════════════════════════════════════════════════════ */

/* Append text with the special characters of the WIFI: format escaped */
static bool append_escaped(char *out, size_t out_len, size_t *pos, const char *text)
{
  for (const char *c = text; *c; c++)
  {
    bool special = strchr("\\;,:\"", *c) != NULL;
    if (*pos + (special ? 2 : 1) >= out_len)
      return false;
    if (special)
      out[(*pos)++] = '\\';
    out[(*pos)++] = *c;
  }
  out[*pos] = '\0';
  return true;
}

static bool append_text(char *out, size_t out_len, size_t *pos, const char *text)
{
  size_t len = strlen(text);
  if (*pos + len >= out_len)
    return false;
  memcpy(out + *pos, text, len + 1);
  *pos += len;
  return true;
}

bool wifi_qr_payload(char *out, size_t out_len, const char *ssid, const char *password)
{
  if (out_len == 0)
    return false;
  size_t pos = 0;
  out[0] = '\0';
  bool secured = password && password[0] != '\0';
  bool ok = append_text(out, out_len, &pos, secured ? "WIFI:T:WPA;S:" : "WIFI:T:nopass;S:") &&
            append_escaped(out, out_len, &pos, ssid) && append_text(out, out_len, &pos, ";");
  if (ok && secured)
    ok = append_text(out, out_len, &pos, "P:") && append_escaped(out, out_len, &pos, password) &&
         append_text(out, out_len, &pos, ";");
  ok = ok && append_text(out, out_len, &pos, ";");
  if (!ok)
    out[0] = '\0';
  return ok;
}

/* ═══════════════════════════════════════════════════════════════════
 * WireGuard configuration import
 * ═══════════════════════════════════════════════════════════════════ */

static bool is_wg_key(const char *key)
{
  if (strlen(key) != 44 || key[43] != '=')
    return false;
  for (int i = 0; i < 43; i++)
    if (!isalnum((unsigned char)key[i]) && key[i] != '+' && key[i] != '/')
      return false;
  return true;
}

/* Copy a key; one too long for the field is marked invalid instead of cut */
static void copy_key(char *dst, size_t dst_len, const char *value)
{
  if (strlen(value) >= dst_len)
    snprintf(dst, dst_len, "!");
  else
    snprintf(dst, dst_len, "%s", value);
}

static char *trim(char *s)
{
  while (isspace((unsigned char)*s))
    s++;
  char *end = s + strlen(s);
  while (end > s && isspace((unsigned char)end[-1]))
    *--end = '\0';
  return s;
}

static void add_warning(wg_import_t *out, const char *warning)
{
  if (strstr(out->warnings, warning))
    return; // once is enough
  size_t len = strlen(out->warnings);
  snprintf(out->warnings + len, sizeof(out->warnings) - len, "%s%s", len ? "; " : "", warning);
}

static bool fail(char *error, size_t error_len, const char *message)
{
  snprintf(error, error_len, "%s", message);
  return false;
}

bool parse_wireguard_conf(const char *text, wg_import_t *out, char *error, size_t error_len)
{
  memset(out, 0, sizeof(*out));
  enum { NONE, INTERFACE, PEER, OTHER } section = NONE;
  int peers = 0;
  bool have_interface = false, have_allowed = false;
  char allowed[512] = {0}; // AllowedIPs of the first peer (all lines joined)
  char line[512];

  const char *p = text;
  while (*p)
  {
    size_t len = strcspn(p, "\r\n");
    if (len >= sizeof(line))
      return fail(error, error_len, "A line of the file is too long");
    memcpy(line, p, len);
    line[len] = '\0';
    p += len;
    while (*p == '\r' || *p == '\n')
      p++;

    char *comment = strpbrk(line, "#;");
    if (comment)
      *comment = '\0';
    char *l = trim(line);
    if (*l == '\0')
      continue;

    if (*l == '[')
    {
      if (strcasecmp(l, "[Interface]") == 0)
      {
        section = INTERFACE;
        have_interface = true;
      }
      else if (strcasecmp(l, "[Peer]") == 0)
      {
        section = PEER;
        if (++peers == 2)
          add_warning(out, "only the first [Peer] is used");
      }
      else
        section = OTHER;
      continue;
    }

    char *eq = strchr(l, '=');
    if (!eq)
      continue;
    *eq = '\0';
    char *key = trim(l);
    char *value = trim(eq + 1);
    // The value keeps the '=' padding of keys: the line is split at the first '='
    if (section == INTERFACE && strcasecmp(key, "PrivateKey") == 0)
      copy_key(out->private_key, sizeof(out->private_key), value);
    else if (section == INTERFACE && strcasecmp(key, "Address") == 0)
    {
      char list[256];
      snprintf(list, sizeof(list), "%s", value);
      for (char *item = strtok(list, ", "); item; item = strtok(NULL, ", "))
      {
        if (strchr(item, ':'))
        {
          add_warning(out, "IPv6 entries ignored");
          continue;
        }
        if (out->address[0] == '\0')
        {
          char ip[16], mask[16];
          if (!parse_cidr(item, ip, sizeof(ip), mask, sizeof(mask)))
            return fail(error, error_len, "Address is not a valid IPv4 address");
          snprintf(out->address, sizeof(out->address), "%s%s", item, strchr(item, '/') ? "" : "/32");
        }
      }
    }
    else if (section == INTERFACE && strcasecmp(key, "DNS") == 0)
    {
      char list[256];
      snprintf(list, sizeof(list), "%s", value);
      for (char *item = strtok(list, ", "); item; item = strtok(NULL, ", "))
      {
        uint32_t a;
        if (parse_ipv4(item, &a))
        {
          if (out->dns[0] == '\0')
            snprintf(out->dns, sizeof(out->dns), "%s", item);
        }
        else if (strchr(item, ':'))
          add_warning(out, "IPv6 entries ignored");
        else
          add_warning(out, "DNS search domains ignored");
      }
    }
    else if (section == PEER && peers == 1)
    {
      if (strcasecmp(key, "PublicKey") == 0)
        copy_key(out->peer_public_key, sizeof(out->peer_public_key), value);
      else if (strcasecmp(key, "PresharedKey") == 0)
        copy_key(out->preshared_key, sizeof(out->preshared_key), value);
      else if (strcasecmp(key, "Endpoint") == 0)
      {
        if (value[0] == '[')
          return fail(error, error_len, "IPv6 endpoints are not supported - use an IPv4 address or a host name");
        char *colon = strrchr(value, ':');
        long port = 51820;
        if (colon)
        {
          char *end;
          port = strtol(colon + 1, &end, 10);
          if (end == colon + 1 || *end != '\0' || port < 1 || port > 65535)
            return fail(error, error_len, "Endpoint port must be 1-65535");
          *colon = '\0';
        }
        if (value[0] == '\0' || strlen(value) >= sizeof(out->endpoint_host))
          return fail(error, error_len, "Endpoint host is missing or too long");
        snprintf(out->endpoint_host, sizeof(out->endpoint_host), "%s", value);
        out->endpoint_port = (uint16_t)port;
      }
      else if (strcasecmp(key, "PersistentKeepalive") == 0)
      {
        char *end;
        long keepalive = strtol(value, &end, 10);
        if (end == value || *end != '\0' || keepalive < 0 || keepalive > 65535)
          return fail(error, error_len, "PersistentKeepalive must be 0-65535 seconds");
        out->keepalive = (uint16_t)keepalive;
      }
      else if (strcasecmp(key, "AllowedIPs") == 0)
      {
        have_allowed = true;
        size_t used = strlen(allowed);
        snprintf(allowed + used, sizeof(allowed) - used, "%s%s", used ? "," : "", value);
      }
    }
  }

  if (!have_interface)
    return fail(error, error_len, "No [Interface] section - is this a WireGuard configuration file?");
  if (peers == 0)
    return fail(error, error_len, "No [Peer] section");
  if (!is_wg_key(out->private_key))
    return fail(error, error_len, "PrivateKey is missing or not a 44 character base64 key");
  if (!is_wg_key(out->peer_public_key))
    return fail(error, error_len, "Peer PublicKey is missing or not a 44 character base64 key");
  if (out->preshared_key[0] && !is_wg_key(out->preshared_key))
    return fail(error, error_len, "PresharedKey is not a 44 character base64 key");
  if (out->address[0] == '\0')
    return fail(error, error_len, "No IPv4 Address in [Interface]");
  if (out->endpoint_host[0] == '\0')
    return fail(error, error_len, "Peer Endpoint is missing");

  // The repeater sits behind NAT: keepalive keeps the mapping open
  if (out->keepalive == 0)
  {
    out->keepalive = 25;
    add_warning(out, "PersistentKeepalive set to 25 s");
  }

  // AllowedIPs: everything (0.0.0.0/0, or the two halves /1) = full tunnel
  out->full_tunnel = !have_allowed;
  if (!have_allowed)
    add_warning(out, "no AllowedIPs - full tunnel");
  bool low_half = false, high_half = false;
  int networks = 0;
  for (char *item = strtok(allowed, ", "); item; item = strtok(NULL, ", "))
  {
    if (strchr(item, ':'))
    {
      add_warning(out, "IPv6 entries ignored");
      continue;
    }
    uint32_t net, mask;
    if (parse_split_networks(item, &net, &mask, 1) != 1)
      return fail(error, error_len, "AllowedIPs has an entry that is not an IPv4 network");
    if (mask == 0)
      out->full_tunnel = true;
    const uint8_t *bytes = (const uint8_t *)&net;
    const uint8_t *mask_bytes = (const uint8_t *)&mask;
    if (mask_bytes[0] == 0x80 && mask_bytes[1] == 0 && mask_bytes[2] == 0 && mask_bytes[3] == 0)
    {
      if (bytes[0] == 0)
        low_half = true;
      else if (bytes[0] == 128)
        high_half = true;
    }
    size_t used = strlen(out->split);
    if (used + strlen(item) + 3 >= sizeof(out->split))
      return fail(error, error_len, "AllowedIPs has too many networks for the split tunnel");
    snprintf(out->split + used, sizeof(out->split) - used, "%s%s", used ? ", " : "", item);
    networks++;
  }
  if (low_half && high_half)
    out->full_tunnel = true;
  if (out->full_tunnel)
    out->split[0] = '\0';
  else if (networks == 0)
    return fail(error, error_len, "AllowedIPs has no IPv4 networks");
  else
  {
    uint32_t nets[8], masks[8];
    if (parse_split_networks(out->split, nets, masks, 8) < 0)
      return fail(error, error_len, "AllowedIPs has more than 8 IPv4 networks (the split tunnel limit)");
  }
  return true;
}
