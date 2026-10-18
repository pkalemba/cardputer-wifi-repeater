"""
PlatformIO post-build script: merges the bootloader, partition table and
application into a single factory image that is flashed at offset 0x0:

    esptool.py --chip esp32s3 write_flash 0x0 .pio/build/<env>/factory.bin

Images, offsets and flash parameters are the same ones `pio run -t upload`
uses, so flashing the factory image is equivalent to a normal upload.
"""

Import("env")  # noqa: F821 - provided by PlatformIO (SCons)


def merge_factory_image(source, target, env):
    board = env.BoardConfig()
    factory = env.subst("$BUILD_DIR/factory.bin")

    # Bootloader and partition table, then the application
    images = [(offset, env.subst(path)) for offset, path in env.get("FLASH_EXTRA_IMAGES", [])]
    images.append((env.subst("$ESP32_APP_OFFSET"), target[0].get_abspath()))

    cmd = [
        '"$PYTHONEXE"', '"$OBJCOPY"',
        "--chip", board.get("build.mcu"),
        "merge_bin",
        "-o", '"%s"' % factory,
        "--flash_mode", env.subst("${__get_board_flash_mode(__env__)}"),
        "--flash_freq", env.subst("${__get_board_f_image(__env__)}"),
        "--flash_size", board.get("upload.flash_size", "keep"),
    ]
    for offset, path in images:
        cmd += [offset, '"%s"' % path]

    return env.Execute(env.VerboseAction(" ".join(cmd), "Building factory image %s" % factory))


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", merge_factory_image)  # noqa: F821
