#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Linaro Limited
#

import argparse
import array
import os
import re


def get_args():

        parser = argparse.ArgumentParser(description='Converts a binary file '
                                         'into C source file defining binary '
                                         'data as a constant byte array.')

        parser.add_argument('--bin', required=True,
                            help='Path to the input binary file')

        parser.add_argument('--vname', required=True,
                            help='Variable name for the generated table in '
                            'the output C source file.')

        parser.add_argument('--out', required=True,
                            help='Path for the generated C file')

        return parser.parse_args()


def main():

        args = get_args()

        with open(args.bin, 'rb') as indata:
                bytes = indata.read()
                size = len(bytes)

        f = open(args.out, 'w')
        f.write('/* Generated from ' + args.bin + ' by ' +
                os.path.basename(__file__) + ' */\n\n')
        f.write('#include <compiler.h>\n')
        f.write('#include <stdint.h>\n')
        f.write('__extension__ const uint8_t ' + args.vname + '[] ' +
                ' __aligned(__alignof__(uint64_t)) = {\n')
        i = 0
        while i < size:
                if i % 8 == 0:
                        f.write('\t\t')
                f.write('0x' + '{:02x}'.format(bytes[i]) + ',')
                i = i + 1
                if i % 8 == 0 or i == size:
                        f.write('\n')
                else:
                        f.write(' ')
        f.write('};\n')
        f.close()


if __name__ == "__main__":
        main()
