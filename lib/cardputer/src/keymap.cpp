/*
 * Keyboard map of the Cardputer ADV - see keymap.h
 */

#include "keymap.h"

/* Same layout as the M5Cardputer library: {normal, shift} per key */
static const uint8_t KEY_MAP[4][14][2] = {
    {{'`', '~'}, {'1', '!'}, {'2', '@'}, {'3', '#'}, {'4', '$'}, {'5', '%'}, {'6', '^'},
     {'7', '&'}, {'8', '*'}, {'9', '('}, {'0', ')'}, {'-', '_'}, {'=', '+'}, {KC_BACKSPACE, KC_BACKSPACE}},
    {{KC_TAB, KC_TAB}, {'q', 'Q'}, {'w', 'W'}, {'e', 'E'}, {'r', 'R'}, {'t', 'T'}, {'y', 'Y'},
     {'u', 'U'}, {'i', 'I'}, {'o', 'O'}, {'p', 'P'}, {'[', '{'}, {']', '}'}, {'\\', '|'}},
    {{KC_FN, KC_FN}, {KC_SHIFT, KC_SHIFT}, {'a', 'A'}, {'s', 'S'}, {'d', 'D'}, {'f', 'F'}, {'g', 'G'},
     {'h', 'H'}, {'j', 'J'}, {'k', 'K'}, {'l', 'L'}, {';', ':'}, {'\'', '"'}, {KC_ENTER, KC_ENTER}},
    {{KC_CTRL, KC_CTRL}, {KC_OPT, KC_OPT}, {KC_ALT, KC_ALT}, {'z', 'Z'}, {'x', 'X'}, {'c', 'C'}, {'v', 'V'},
     {'b', 'B'}, {'n', 'N'}, {'m', 'M'}, {',', '<'}, {'.', '>'}, {'/', '?'}, {' ', ' '}},
};

bool keyboard_key_position(uint8_t key_number, int *row, int *column)
{
  if (key_number < 1 || key_number > 70)
    return false;
  int raw_row = (key_number - 1) / 10;
  int raw_column = (key_number - 1) % 10;
  if (raw_row > 6 || raw_column > 7)
    return false;
  // M5Cardputer library remap of the 7x8 matrix to the 4x14 layout
  *column = raw_row * 2 + (raw_column > 3 ? 1 : 0);
  *row = raw_column % 4;
  return true;
}

uint8_t keyboard_key_code(uint8_t key_number, bool shift, bool fn)
{
  int row, column;
  if (!keyboard_key_position(key_number, &row, &column))
    return KC_NONE;
  uint8_t normal = KEY_MAP[row][column][0];
  if (fn)
  {
    switch (normal)
    {
    case '`':
      return KC_ESC;
    case ';':
      return KC_UP;
    case '.':
      return KC_DOWN;
    case ',':
      return KC_LEFT;
    case '/':
      return KC_RIGHT;
    default:
      break;
    }
  }
  return KEY_MAP[row][column][shift ? 1 : 0];
}
