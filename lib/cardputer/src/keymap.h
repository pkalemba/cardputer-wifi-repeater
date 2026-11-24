/*
 * Keyboard map of the Cardputer ADV (TCA8418 key numbers -> key codes).
 * No hardware dependencies - unit tested on the host (test/host).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Printable keys give their ASCII code, the others these codes */
#define KC_NONE 0x00
#define KC_BACKSPACE 0x08
#define KC_TAB 0x09
#define KC_ENTER 0x0D
#define KC_ESC 0x1B
#define KC_UP 0x81
#define KC_DOWN 0x82
#define KC_LEFT 0x83
#define KC_RIGHT 0x84
#define KC_SHIFT 0x90
#define KC_FN 0x91
#define KC_CTRL 0x92
#define KC_OPT 0x93
#define KC_ALT 0x94

/*
 * Position on the 4x14 keyboard (row 0 = number row, column 0 = left) of a
 * TCA8418 key number (row * 10 + column + 1 of its 7x8 matrix, as wired on
 * the Cardputer ADV). False for numbers outside the matrix.
 */
bool keyboard_key_position(uint8_t key_number, int *row, int *column);

/*
 * Key code of a key number with the shift / fn modifiers held. fn gives the
 * arrows on ; . , / and Esc on the ` key.
 */
uint8_t keyboard_key_code(uint8_t key_number, bool shift, bool fn);
