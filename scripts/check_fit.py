#!/usr/bin/env python3
"""
Check that a firmware build fits the M5Stack Cardputer (ESP32-S3FN8: 8 MB flash,
no PSRAM, 512 KB internal RAM).

    pip install esp-idf-size        # for the RAM check
    python scripts/check_fit.py [BUILD_DIR] [--sdkconfig FILE]

Exits with 1 when something does not fit and warns when it gets close. In GitHub
Actions the results also go to the job summary and show up as annotations.
"""

import argparse
import glob
import json
import os
import re
import struct
import subprocess
import sys

CARDPUTER_FLASH = 8 * 1024 * 1024  # ESP32-S3FN8
BOOTLOADER_OFFSET = 0x0            # ESP32-S3
APP_WARN_PERCENT = 90

# Free internal RAM after static allocation. At runtime the heap has to hold the
# display framebuffer (63 KiB, DMA capable), WiFi AP+STA buffers, lwIP/NAPT,
# task stacks and the web server.
MIN_FREE_RAM = 128 * 1024
WARN_FREE_RAM = 192 * 1024

PASS, WARN, FAIL = 'pass', 'warning', 'FAIL'
ICONS = {PASS: '✅', WARN: '⚠️', FAIL: '❌'}


def read_sdkconfig(path):
    config = {}
    with open(path) as f:
        for line in f:
            match = re.match(r'^(CONFIG_\w+)=(.*)$', line.strip())
            if match:
                config[match.group(1)] = match.group(2).strip('"')
    return config


def read_partitions(path):
    """Parse an ESP-IDF binary partition table"""
    with open(path, 'rb') as f:
        data = f.read()

    partitions = []
    for pos in range(0, len(data) - 31, 32):
        magic, ptype, subtype, offset, size, label, _flags = struct.unpack_from('<HBBII16sI', data, pos)
        if magic == 0xEBEB:  # MD5 checksum entry
            continue
        if magic != 0x50AA:  # end of the table
            break
        partitions.append({
            'type': ptype,
            'subtype': subtype,
            'offset': offset,
            'size': size,
            'label': label.rstrip(b'\0').decode(errors='replace'),
        })
    return partitions


def read_ram_usage(map_file):
    """Static RAM usage per memory type from esp-idf-size: ({name: info}, error)"""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'esp_idf_size', '--format', 'json2', map_file],
            capture_output=True, text=True, check=True)
        layout = json.loads(result.stdout)['layout']
    except subprocess.CalledProcessError as e:
        return None, 'esp-idf-size failed: ' + (e.stderr.strip().splitlines() or ['unknown error'])[-1]
    except (OSError, ValueError, KeyError) as e:
        return None, 'esp-idf-size failed: %s' % e
    return {mem['name']: mem for mem in layout}, None


def mib(size):
    return ('%.2f' % (size / (1024 * 1024))).rstrip('0').rstrip('.') + ' MB'


class Report:
    def __init__(self):
        self.rows = []

    def add(self, check, usage, limit, status):
        self.rows.append((check, usage, limit, status))

    def add_size(self, check, used, limit, limit_note, warn_percent=None):
        percent = used * 100.0 / limit if limit else float('inf')
        status = PASS
        if used > limit:
            status = FAIL
        elif warn_percent is not None and percent >= warn_percent:
            status = WARN
        self.add(check, '{:,} B ({:.1f} %)'.format(used, percent), '{:,} B {}'.format(limit, limit_note), status)

    def failed(self):
        return any(row[3] == FAIL for row in self.rows)

    def print_text(self):
        for check, usage, limit, status in self.rows:
            print('[%-7s] %-34s %-36s limit: %s' % (status, check, usage, limit))

    def markdown(self):
        lines = [
            '### Fits the M5Stack Cardputer?',
            '',
            '| | Check | Usage | Limit |',
            '|---|---|---|---|',
        ]
        for check, usage, limit, status in self.rows:
            lines.append('| %s | %s | %s | %s |' % (ICONS[status], check, usage, limit))
        return '\n'.join(lines) + '\n'

    def annotations(self):
        for check, usage, limit, status in self.rows:
            if status != PASS:
                level = 'error' if status == FAIL else 'warning'
                print('::%s title=Cardputer fit: %s::%s (limit: %s)' % (level, check, usage, limit))


def main():
    parser = argparse.ArgumentParser(description='Check that the firmware fits the M5Stack Cardputer.')
    parser.add_argument('build_dir', nargs='?', default='.pio/build/m5stack-stamps3')
    parser.add_argument('--sdkconfig', default='sdkconfig.m5stack-stamps3')
    parser.add_argument('--require-ram', action='store_true',
                        help='fail instead of warn when the RAM usage cannot be determined')
    args = parser.parse_args()

    config = read_sdkconfig(args.sdkconfig)
    report = Report()

    def file_size(name):
        path = os.path.join(args.build_dir, name)
        if not os.path.isfile(path):
            report.add(name, 'missing', 'built by `pio run`', FAIL)
            return None
        return os.path.getsize(path)

    # Chip and PSRAM
    target = config.get('CONFIG_IDF_TARGET', 'unknown')
    report.add('Chip', target, 'esp32s3', PASS if target == 'esp32s3' else FAIL)
    psram = config.get('CONFIG_SPIRAM') == 'y'
    report.add('PSRAM', 'required' if psram else 'not used', 'none on the Cardputer', FAIL if psram else PASS)

    # Bootloader has to end before the partition table
    table_offset = int(config.get('CONFIG_PARTITION_TABLE_OFFSET', '0x8000'), 0)
    bootloader = file_size('bootloader.bin')
    if bootloader is not None:
        report.add_size('Bootloader', bootloader, table_offset - BOOTLOADER_OFFSET,
                        '(partition table at 0x%x)' % table_offset)

    # Application has to fit its partition
    partitions = read_partitions(os.path.join(args.build_dir, 'partitions.bin'))
    app_partition = next((p for p in partitions if p['type'] == 0 and p['subtype'] in (0x00, 0x10)), None)
    app = file_size('firmware.bin')
    if app is not None:
        if app_partition is None:
            report.add('Application', '{:,} B'.format(app), 'no factory/ota_0 partition', FAIL)
        else:
            report.add_size('Application', app, app_partition['size'],
                            '(%s partition)' % app_partition['label'], APP_WARN_PERCENT)

    # Partitions have to fit the flash: the configured size and the chip
    flash_size = config.get('CONFIG_ESPTOOLPY_FLASHSIZE', '4MB')
    configured_flash = int(flash_size[:-2]) * 1024 * 1024 if flash_size.endswith('MB') else CARDPUTER_FLASH
    flash_limit = min(configured_flash, CARDPUTER_FLASH)
    if partitions:
        layout_end = max(p['offset'] + p['size'] for p in partitions)
        report.add('Partition table', 'ends at 0x%x (%s)' % (layout_end, mib(layout_end)),
                   '%s configured, %s on the Cardputer' % (mib(configured_flash), mib(CARDPUTER_FLASH)),
                   PASS if layout_end <= flash_limit else FAIL)
    else:
        report.add('Partition table', 'no partitions found', 'partitions.bin', FAIL)

    factory = file_size('factory.bin')
    if factory is not None:
        report.add_size('Factory image', factory, flash_limit, '(flash)')

    # Free internal RAM after static allocation (code in IRAM, data, bss)
    map_files = glob.glob(os.path.join(args.build_dir, '*.map'))
    if map_files:
        ram, error = read_ram_usage(map_files[0])
    else:
        ram, error = None, 'no linker map file in ' + args.build_dir
    if ram and 'DIRAM' in ram:
        diram = ram['DIRAM']
        status = PASS
        if diram['free'] < MIN_FREE_RAM:
            status = FAIL
        elif diram['free'] < WARN_FREE_RAM:
            status = WARN
        report.add('Free internal RAM (DIRAM)',
                   '{:,} B free of {:,} B'.format(diram['free'], diram['total']),
                   'at least %d KiB (warning below %d KiB)' % (MIN_FREE_RAM // 1024, WARN_FREE_RAM // 1024),
                   status)
    else:
        report.add('Free internal RAM', 'unknown', error or 'esp-idf-size reported no DIRAM',
                   FAIL if args.require_ram else WARN)

    report.print_text()
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        report.annotations()
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as f:
            f.write(report.markdown())

    if report.failed():
        print('The firmware does not fit the M5Stack Cardputer.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
