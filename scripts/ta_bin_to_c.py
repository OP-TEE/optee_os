#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017, Linaro Limited
#

import argparse
import array
from elftools.elf.elffile import ELFFile
import os
import re
import struct
import uuid
import zlib


def get_args():
    parser = argparse.ArgumentParser(
        description='Converts a Trusted '
        'Application ELF file into a C source file, ready for '
        'inclusion in the TEE binary as an "early TA".')

    parser.add_argument('--out', required=True,
                        help='Name of the output C file')

    parser.add_argument(
        '--ta',
        required=True,
        help='Path to the TA binary. File name has to be: <uuid>.* '
        'such as: 8aaaf200-2450-11e4-abe2-0002a5d5c51b.stripped.elf')

    parser.add_argument(
        '--compress',
        dest="compress",
        action="store_true",
        help='Compress the TA using the DEFLATE '
        'algorithm')

    return parser.parse_args()


def get_name(obj):
    # Symbol or section .name might be a byte array or a string, we want a
    # string
    try:
        name = obj.name.decode()
    except (UnicodeDecodeError, AttributeError):
        name = obj.name
    return name


def ta_get_flags(ta_f):
    with open(ta_f, 'rb') as f:
        elffile = ELFFile(f)

        for s in elffile.iter_sections():
            if get_name(s) == '.ta_head':
                return struct.unpack('<16x4xI', s.data()[:24])[0]

        raise Exception('.ta_head section not found')


def main():
    args = get_args()

    ta_uuid = uuid.UUID(re.sub(r'\..*', '', os.path.basename(args.ta)))

    with open(args.ta, 'rb') as ta:
        bytes = ta.read()
        uncompressed_size = len(bytes)
        if args.compress:
            bytes = zlib.compress(bytes)
        size = len(bytes)

    f = open(args.out, 'w')
    f.write('/* Generated from ' + args.ta + ' by ' +
            os.path.basename(__file__) + ' */\n\n')
    f.write('#include <compiler.h>\n')
    f.write('#include <kernel/early_ta.h>\n\n')
    f.write('__extension__ const struct early_ta __early_ta_' +
            ta_uuid.hex +
            '\n__early_ta __aligned(__alignof__(struct early_ta)) = {\n')
    f.write('\t.flags = 0x{:04x},\n'.format(ta_get_flags(args.ta)))
    f.write('\t.uuid = {\n')
    f.write('\t\t.timeLow = 0x{:08x},\n'.format(ta_uuid.time_low))
    f.write('\t\t.timeMid = 0x{:04x},\n'.format(ta_uuid.time_mid))
    f.write('\t\t.timeHiAndVersion = ' +
            '0x{:04x},\n'.format(ta_uuid.time_hi_version))
    f.write('\t\t.clockSeqAndNode = {\n')
    csn = '{0:02x}{1:02x}{2:012x}'.format(ta_uuid.clock_seq_hi_variant,
                                          ta_uuid.clock_seq_low, ta_uuid.node)
    f.write('\t\t\t')
    f.write(', '.join('0x' + csn[i:i + 2] for i in range(0, len(csn), 2)))
    f.write('\n\t\t},\n\t},\n')
    f.write('\t.size = {:d},\n'.format(size))
    if args.compress:
        f.write('\t.uncompressed_size = '
                '{:d},\n'.format(uncompressed_size))
    f.write('\t.ta = {\n')
    i = 0
    while i < size:
        if i % 8 == 0:
            f.write('\t\t')
        f.write(hex(bytes[i]) + ',')
        i = i + 1
        if i % 8 == 0 or i == size:
            f.write('\n')
        else:
            f.write(' ')
    f.write('\t},\n')
    f.write('};\n')
    f.close()


if __name__ == "__main__":
    main()
