/*
 * M5Stack Cardputer input: the G0 button (all models) and the keyboard of
 * the Cardputer ADV (TCA8418 key matrix controller on I2C). The original
 * Cardputer's keyboard is not supported - apps stay usable with G0.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "keymap.h"

#define BUTTON_G0_PIN 0 // active low; also a strapping pin (download mode at reset)

void button_g0_init(void);
bool button_g0_pressed(void);

/* False when there is no TCA8418 (not a Cardputer ADV) */
bool keyboard_init(void);
bool keyboard_available(void);

/*
 * Key codes (keymap.h) of the keys pressed since the last call, with
 * shift / fn applied (the modifiers themselves are not returned)
 */
int keyboard_read_keys(uint8_t *codes, int max_codes);
