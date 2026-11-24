/* Minimal test macros shared by the host unit tests */
#pragma once

#include <stdio.h>
#include <string.h>

extern int checks;
extern int failures;

#define CHECK(cond)                                                       \
  do                                                                      \
  {                                                                       \
    checks++;                                                             \
    if (!(cond))                                                          \
    {                                                                     \
      failures++;                                                         \
      printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
    }                                                                     \
  } while (0)

#define CHECK_EQ(a, b)                                                                              \
  do                                                                                                \
  {                                                                                                 \
    checks++;                                                                                       \
    long long va = (long long)(a), vb = (long long)(b);                                             \
    if (va != vb)                                                                                   \
    {                                                                                               \
      failures++;                                                                                   \
      printf("  FAIL %s:%d: %s == %s (%lld != %lld)\n", __FILE__, __LINE__, #a, #b, va, vb);       \
    }                                                                                               \
  } while (0)

#define CHECK_STR(a, b)                                                                         \
  do                                                                                            \
  {                                                                                             \
    checks++;                                                                                   \
    if (strcmp((a), (b)) != 0)                                                                  \
    {                                                                                           \
      failures++;                                                                               \
      printf("  FAIL %s:%d: %s == \"%s\" (got \"%s\")\n", __FILE__, __LINE__, #a, (b), (a));  \
    }                                                                                           \
  } while (0)

#define TEST(name) static void name(void)
#define RUN(name)              \
  do                           \
  {                            \
    int before = failures;     \
    name();                    \
    printf("%s %s\n", failures == before ? "ok  " : "FAIL", #name); \
  } while (0)

void run_tracker_tests(void);
void run_roomscan_tests(void);
