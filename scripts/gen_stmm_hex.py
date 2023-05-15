#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Linaro Limited
#

import argparse
import sys
import zlib


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--input',
                        required=True, type=argparse.FileType('rb'),
                        help='The input StMM binary (BL32_AP_MM.fd)')

    parser.add_argument('--output',
                        required=True, type=argparse.FileType('w'),
                        help='The output stmm_hex.c')

    return parser.parse_args()


def main():
    args = get_args()
    inf = args.input
    outf = args.output

    bytes = inf.read()
    uncompressed_size = len(bytes)
    bytes = zlib.compress(bytes)
    size = len(bytes)

    outf.write('/* Automatically generated, do no edit */\n')
    outf.write('const unsigned char stmm_image[] = {\n')
    i = 0
    while i < size:
        if i % 8 == 0:
            outf.write('\t')
        outf.write('0x{:02x},'.format(bytes[i]))
        i = i + 1
        if i % 8 == 0 or i == size:
            outf.write('\n')
        else:
            outf.write(' ')
    outf.write('};\n')

    outf.write('const unsigned int stmm_image_size = sizeof(stmm_image);\n')
    outf.write('const unsigned int stmm_image_uncompressed_size = '
               '{:d};\n'.format(uncompressed_size))

    inf.close()
    outf.close()


if __name__ == "__main__":
    main()
