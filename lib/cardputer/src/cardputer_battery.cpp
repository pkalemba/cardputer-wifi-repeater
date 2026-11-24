/*
 * M5Stack Cardputer battery gauge - see cardputer_battery.h
 */

#include "cardputer_battery.h"

#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_log.h"

#define BATTERY_ADC_PIN 10 // battery voltage through a 1:2 divider
#define BATTERY_DIVIDER 2

static adc_oneshot_unit_handle_t battery_adc = NULL;
static adc_channel_t battery_channel;
static adc_cali_handle_t battery_cali = NULL;
static int battery_mv = -1;

void battery_init(void)
{
  adc_unit_t unit;
  if (adc_oneshot_io_to_channel(BATTERY_ADC_PIN, &unit, &battery_channel) != ESP_OK)
    return;

  adc_oneshot_unit_init_cfg_t unit_config = {};
  unit_config.unit_id = unit;
  if (adc_oneshot_new_unit(&unit_config, &battery_adc) != ESP_OK)
  {
    ESP_LOGW("battery", "Battery ADC not available");
    battery_adc = NULL;
    return;
  }

  adc_oneshot_chan_cfg_t channel_config = {};
  channel_config.atten = ADC_ATTEN_DB_12;
  channel_config.bitwidth = ADC_BITWIDTH_12;
  adc_oneshot_config_channel(battery_adc, battery_channel, &channel_config);

  adc_cali_curve_fitting_config_t cali_config = {};
  cali_config.unit_id = unit;
  cali_config.chan = battery_channel;
  cali_config.atten = ADC_ATTEN_DB_12;
  cali_config.bitwidth = ADC_BITWIDTH_12;
  if (adc_cali_create_scheme_curve_fitting(&cali_config, &battery_cali) != ESP_OK)
    battery_cali = NULL;
}

void battery_sample(void)
{
  if (!battery_adc)
    return;

  int sum = 0;
  int count = 0;
  for (int i = 0; i < 16; i++)
  {
    int raw, mv;
    if (adc_oneshot_read(battery_adc, battery_channel, &raw) != ESP_OK)
      continue;
    if (battery_cali && adc_cali_raw_to_voltage(battery_cali, raw, &mv) == ESP_OK)
      sum += mv;
    else
      sum += raw * 3100 / 4095; // uncalibrated estimate for 12 dB attenuation
    count++;
  }
  if (count == 0)
    return;

  int mv = sum / count * BATTERY_DIVIDER;
  battery_mv = battery_mv < 0 ? mv : (battery_mv * 3 + mv) / 4;
}

int battery_voltage_mv(void) { return battery_mv; }

int battery_percent(void)
{
  if (battery_mv < 0)
    return -1;
  int level = (battery_mv - 3300) * 100 / 800;
  return level < 0 ? 0 : (level > 100 ? 100 : level);
}
