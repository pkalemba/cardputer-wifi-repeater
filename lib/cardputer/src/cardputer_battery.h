/* M5Stack Cardputer battery gauge: GPIO10 through a 1:2 divider */
#pragma once

void battery_init(void);
/* 16 readings, smoothed over time - call every few seconds */
void battery_sample(void);
/* Smoothed voltage in mV, -1 = unknown */
int battery_voltage_mv(void);
/* Level 0-100 % (same mapping as M5Unified: 3.3 V = 0 %, 4.1 V = 100 %), -1 = unknown */
int battery_percent(void);
