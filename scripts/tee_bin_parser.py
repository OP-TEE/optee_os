#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2016, Linaro Limited
import struct


def main():
    with open("../out/arm/core/tee.bin", "rb") as f:
        data = f.read(4)
        magic = struct.unpack('<I', data)
        print("Magic: \t\t0x%08x" % magic)

        data = f.read(1)
        version = struct.unpack('<B', data)
        print("Version: \t0x%02x" % version)

        data = f.read(1)
        arch_id = struct.unpack('<B', data)
        print("ArchID: \t0x%02x" % arch_id)

        data = f.read(2)
        flags = struct.unpack('<H', data)
        print("Arch Flags: \t0x%04x" % arch_id)

        data = f.read(4)
        init_size = struct.unpack('<I', data)
        print("Init size: \t0x%04x" % init_size)

        data = f.read(4)
        laddr_h = struct.unpack('<I', data)
        print("Load addr high:\t0x%04x" % laddr_h)

        data = f.read(4)
        laddr_l = struct.unpack('<I', data)
        print("Load addr low: \t0x%04x" % laddr_l)

        data = f.read(4)
        mem_usage = struct.unpack('<I', data)
        print("Mem usage: \t0x%04x" % mem_usage)

        data = f.read(4)
        pgd_size = struct.unpack('<I', data)
        print("Pages size: \t0x%04x" % pgd_size)


if __name__ == "__main__":
    main()
