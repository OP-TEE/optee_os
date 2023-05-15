#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
#
# Derived from plat-stm32mp1/scripts/stm32image.py
#

import argparse
import struct
import mmap

header_size = 0x200
ext_magic_number = 0x12348765
version = 0x00002710


def get_size(file):
    file.seek(0, 2)        # End of the file
    size = file.tell()
    return size


def aml_set_header(dest_fd, entry, res_mem_start, res_mem_size, sec_mem_start,
                   sec_mem_size):
    dest_fd.seek(0, 0)

    dest_fd.write(struct.pack('<IIQQQQQ',
                  ext_magic_number,
                  version,
                  entry,
                  res_mem_start,
                  res_mem_size,
                  sec_mem_start,
                  sec_mem_size))

    # Padding
    dest_fd.write(b'\x00' * 464)
    dest_fd.close()


def aml_create_header_file(source, dest, entry, res_mem_start, res_mem_size,
                           sec_mem_start, sec_mem_size):
    dest_fd = open(dest, 'w+b')
    src_fd = open(source, 'rb')

    dest_fd.write(b'\x00' * header_size)

    sizesrc = get_size(src_fd)
    if sizesrc > 0:
        mmsrc = mmap.mmap(src_fd.fileno(), 0, access=mmap.ACCESS_READ)
        dest_fd.write(mmsrc[:sizesrc])
        mmsrc.close()

    src_fd.close()

    aml_set_header(dest_fd, entry, res_mem_start, res_mem_size, sec_mem_start,
                   sec_mem_size)

    dest_fd.close()


def auto_int(x):
    return int(x, 0)


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--source',
                        required=True,
                        help='Source file')

    parser.add_argument('--dest',
                        required=True,
                        help='Destination file')

    parser.add_argument('--entry',
                        required=True,
                        type=auto_int,
                        help='Entry point')

    parser.add_argument('--res_mem_start',
                        required=True,
                        type=auto_int,
                        help='Reserved memory start')

    parser.add_argument('--res_mem_size',
                        required=True,
                        type=auto_int,
                        help='Reserved memory size')

    parser.add_argument('--sec_mem_start',
                        required=True,
                        type=auto_int,
                        help='Secure memory start')

    parser.add_argument('--sec_mem_size',
                        required=True,
                        type=auto_int,
                        help='Secure memory size')

    return parser.parse_args()


def main():
    args = get_args()

    source_file = args.source
    destination_file = args.dest
    entry_point = args.entry
    res_mem_start = args.res_mem_start
    res_mem_size = args.res_mem_size
    sec_mem_start = args.sec_mem_start
    sec_mem_size = args.sec_mem_size

    aml_create_header_file(source_file,
                           destination_file,
                           entry_point,
                           res_mem_start,
                           res_mem_size,
                           sec_mem_start,
                           sec_mem_size)


if __name__ == "__main__":
    main()
