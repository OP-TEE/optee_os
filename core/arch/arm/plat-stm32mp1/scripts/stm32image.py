#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017-2018, STMicroelectronics
#
import argparse
import struct
import mmap

header_size = 256
hdr_magic_number = 0x324D5453  # magic ='S' 'T' 'M' 0x32
hdr_header_ver_variant = 0
hdr_header_ver_minor = 0
hdr_header_ver_major = 1
hdr_version_number = 0
hdr_option_flags = 1           # bit0=1 no signature
hdr_edcsa_algo = 1


def get_size(file):
    file.seek(0, 2)        # End of the file
    size = file.tell()
    return size


def stm32image_checksum(dest_fd, sizedest):
    csum = 0
    if sizedest < header_size:
        return 0
    dest_fd.seek(header_size, 0)
    length = sizedest - header_size
    while length > 0:
        csum += ord(dest_fd.read(1))
        length -= 1
    return csum


def stm32image_set_header(dest_fd, load, entry, bintype):
    sizedest = get_size(dest_fd)

    checksum = stm32image_checksum(dest_fd, sizedest)

    dest_fd.seek(0, 0)

    # Magic number
    dest_fd.write(struct.pack('<I', hdr_magic_number))

    # Image signature (empty)
    dest_fd.write(b'\x00' * 64)

    # Image checksum ... EDCSA algorithm
    dest_fd.write(struct.pack('<IBBBBIIIIIIII',
                  checksum,
                  hdr_header_ver_variant,
                  hdr_header_ver_minor,
                  hdr_header_ver_major,
                  0,
                  sizedest - header_size,
                  entry,
                  0,
                  load,
                  0,
                  hdr_version_number,
                  hdr_option_flags,
                  hdr_edcsa_algo))

    # EDCSA public key (empty)
    dest_fd.write(b'\x00' * 64)

    # Padding
    dest_fd.write(b'\x00' * 83)
    dest_fd.write(struct.pack('<B', bintype))
    dest_fd.close()


def stm32image_create_header_file(source, dest, load, entry, bintype):
    dest_fd = open(dest, 'w+b')
    src_fd = open(source, 'rb')

    dest_fd.write(b'\x00' * header_size)

    sizesrc = get_size(src_fd)
    if sizesrc > 0:
        mmsrc = mmap.mmap(src_fd.fileno(), 0, access=mmap.ACCESS_READ)
        dest_fd.write(mmsrc[:sizesrc])
        mmsrc.close()

    src_fd.close()

    stm32image_set_header(dest_fd, load, entry, bintype)

    dest_fd.close()


def int_parse(str):
    return int(str, 0)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source',
                        required=True,
                        help='Source file')

    parser.add_argument('--dest',
                        required=True,
                        help='Destination file')

    parser.add_argument('--load',
                        required=True, type=int_parse,
                        help='Load address')

    parser.add_argument('--entry',
                        required=True, type=int_parse,
                        help='Entry point')

    parser.add_argument('--bintype',
                        required=True, type=int_parse,
                        help='Binary identification')

    return parser.parse_args()


def main():
    args = get_args()
    source_file = args.source
    destination_file = args.dest
    load_address = args.load
    entry_point = args.entry
    binary_type = args.bintype

    stm32image_create_header_file(source_file,
                                  destination_file,
                                  load_address,
                                  entry_point,
                                  binary_type)


if __name__ == "__main__":
    main()
