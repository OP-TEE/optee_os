#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2016, Linaro Limited
import struct
import argparse


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--input', required=False,  dest='inf',
                        default='../out/arm/core/tee.bin',
                        help='The input tee.bin')

    return parser.parse_args()


def main():
    args = get_args()

    with open(args.inf, "rb") as f:
        data = f.read(4)
        magic = struct.unpack('<I', data)[0]
        print("Magic: \t\t0x{:08x}".format(magic))

        data = f.read(1)
        version = struct.unpack('<B', data)[0]
        print("Version: \t0x{:02x}".format(version))

        data = f.read(1)
        arch_id = struct.unpack('<B', data)[0]
        print("ArchID: \t0x{:02x}".format(arch_id))

        data = f.read(2)
        flags = struct.unpack('<H', data)[0]
        print("Arch Flags: \t0x{:04x}".format(arch_id))

        data = f.read(4)
        init_size = struct.unpack('<I', data)[0]
        print("Init size: \t0x{:04x}".format(init_size))

        data = f.read(4)
        laddr_h = struct.unpack('<I', data)[0]
        print("Load addr high:\t0x{:04x}".format(laddr_h))

        data = f.read(4)
        laddr_l = struct.unpack('<I', data)[0]
        print("Load addr low: \t0x{:04x}".format(laddr_l))

        data = f.read(4)
        mem_usage = struct.unpack('<I', data)[0]
        print("Mem usage: \t0x{:04x}".format(mem_usage))

        data = f.read(4)
        pgd_size = struct.unpack('<I', data)[0]
        print("Pages size: \t0x{:04x}".format(pgd_size))


if __name__ == "__main__":
    main()
