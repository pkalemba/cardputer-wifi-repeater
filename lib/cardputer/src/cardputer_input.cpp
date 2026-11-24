/*
 * M5Stack Cardputer G0 button and ADV keyboard - see cardputer_input.h
 */

#include "cardputer_input.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"

static const char *TAG = "keyboard";

/* TCA8418 key matrix controller of the Cardputer ADV */
#define KEYBOARD_SDA_PIN 8
#define KEYBOARD_SCL_PIN 9
#define TCA8418_ADDR 0x34
#define TCA8418_REG_CFG 0x01
#define TCA8418_REG_INT_STAT 0x02
#define TCA8418_REG_KEY_LCK_EC 0x03
#define TCA8418_REG_KEY_EVENT_A 0x04
#define TCA8418_REG_KP_GPIO_1 0x1D
#define TCA8418_REG_KP_GPIO_2 0x1E
#define TCA8418_REG_KP_GPIO_3 0x1F
#define TCA8418_KEY_PRESSED 0x80

void button_g0_init(void)
{
  gpio_config_t button_config = {};
  button_config.pin_bit_mask = 1ULL << BUTTON_G0_PIN;
  button_config.mode = GPIO_MODE_INPUT;
  button_config.pull_up_en = GPIO_PULLUP_ENABLE;
  gpio_config(&button_config);
}

bool button_g0_pressed(void) { return gpio_get_level((gpio_num_t)BUTTON_G0_PIN) == 0; }

static i2c_master_dev_handle_t keyboard_dev = NULL;

static esp_err_t tca8418_write(uint8_t reg, uint8_t value)
{
  uint8_t buf[2] = {reg, value};
  return i2c_master_transmit(keyboard_dev, buf, sizeof(buf), 50);
}

static esp_err_t tca8418_read(uint8_t reg, uint8_t *value)
{
  return i2c_master_transmit_receive(keyboard_dev, &reg, 1, value, 1, 50);
}

/*
 * Set up the TCA8418 as a 7x8 key matrix (like the M5Cardputer library).
 * Key events are polled, the interrupt pin is not used.
 */
bool keyboard_init(void)
{
  if (keyboard_dev)
    return true;

  i2c_master_bus_config_t bus_config = {};
  bus_config.i2c_port = -1; // any free controller
  bus_config.sda_io_num = (gpio_num_t)KEYBOARD_SDA_PIN;
  bus_config.scl_io_num = (gpio_num_t)KEYBOARD_SCL_PIN;
  bus_config.clk_source = I2C_CLK_SRC_DEFAULT;
  bus_config.glitch_ignore_cnt = 7;
  bus_config.flags.enable_internal_pullup = true;

  i2c_master_bus_handle_t bus = NULL;
  if (i2c_new_master_bus(&bus_config, &bus) != ESP_OK)
    return false;
  if (i2c_master_probe(bus, TCA8418_ADDR, 50) != ESP_OK)
  {
    ESP_LOGW(TAG, "No TCA8418 found (not a Cardputer ADV?) - keyboard disabled");
    i2c_del_master_bus(bus);
    return false;
  }

  i2c_device_config_t dev_config = {};
  dev_config.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dev_config.device_address = TCA8418_ADDR;
  dev_config.scl_speed_hz = 400000;
  if (i2c_master_bus_add_device(bus, &dev_config, &keyboard_dev) != ESP_OK)
    return false;

  tca8418_write(TCA8418_REG_KP_GPIO_1, 0x7F); // rows 0-6
  tca8418_write(TCA8418_REG_KP_GPIO_2, 0xFF); // columns 0-7
  tca8418_write(TCA8418_REG_KP_GPIO_3, 0x00);
  tca8418_write(TCA8418_REG_CFG, 0x01); // key event interrupt (KE_IEN)

  // Drop events from before the start
  uint8_t event = 0;
  for (int i = 0; i < 10 && tca8418_read(TCA8418_REG_KEY_EVENT_A, &event) == ESP_OK && event != 0; i++)
  {
  }
  tca8418_write(TCA8418_REG_INT_STAT, 0x03);
  ESP_LOGI(TAG, "Keyboard ready");
  return true;
}

bool keyboard_available(void) { return keyboard_dev != NULL; }

int keyboard_read_keys(uint8_t *codes, int max_codes)
{
  static bool shift = false, fn = false;
  if (!keyboard_dev)
    return 0;
  uint8_t count = 0;
  if (tca8418_read(TCA8418_REG_KEY_LCK_EC, &count) != ESP_OK || (count & 0x0F) == 0)
    return 0;

  int stored = 0;
  for (int i = 0; i < (count & 0x0F); i++)
  {
    uint8_t event = 0;
    if (tca8418_read(TCA8418_REG_KEY_EVENT_A, &event) != ESP_OK || event == 0)
      break;
    bool pressed = event & TCA8418_KEY_PRESSED;
    uint8_t code = keyboard_key_code(event & 0x7F, false, false);
    if (code == KC_SHIFT)
      shift = pressed;
    else if (code == KC_FN)
      fn = pressed;
    else if (pressed && stored < max_codes)
      codes[stored++] = keyboard_key_code(event & 0x7F, shift, fn);
  }
  tca8418_write(TCA8418_REG_INT_STAT, 0x01);
  return stored;
}
