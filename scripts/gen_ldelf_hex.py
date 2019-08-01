#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Linaro Limited
#

from __future__ import print_function
from __future__ import division

import argparse
import sys
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.constants import P_FLAGS
except ImportError:
    print("""
***
Can't find elftools module. Probably it is not installed on your system.
You can install this module with

$ apt install python3-pyelftools

if you are using Ubuntu. Or try to search for "pyelftools" or "elftools" in
your package manager if you are using some other distribution.
***
""")
    raise

import struct
import re
from collections import deque


def round_up(n, m):
    if n == 0:
        return 0
    else:
        return (((n - 1) // m) + 1) * m


def emit_load_segments(elffile, outf):
    load_size = 0
    data_size = 0
    next_rwseg_va = 0
    n = 0
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            if n == 0:
                if segment['p_flags'] != (P_FLAGS.PF_R | P_FLAGS.PF_X):
                    print('Expected first load segment to be read/execute')
                    sys.exit(1)
                code_size = segment['p_filesz']
            else:
                if segment['p_flags'] != (P_FLAGS.PF_R | P_FLAGS.PF_W):
                    print('Expected load segment to be read/write')
                    sys.exit(1)
                if next_rwseg_va and segment['p_vaddr'] != next_rwseg_va:
                    print('Expected contiguous read/write segments')
                    print(segment['p_vaddr'])
                    print(next_rwseg_va)
                    sys.exit(1)
                data_size += segment['p_filesz']
                next_rwseg_va = segment['p_vaddr'] + segment['p_filesz']
            load_size += segment['p_filesz']
            n = n + 1

    outf.write(b'const uint8_t ldelf_data[%d]' % round_up(load_size, 4096))
    outf.write(b' __aligned(4096) = {\n')
    i = 0
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            data = segment.data()
            for n in range(segment['p_filesz']):
                if i % 8 == 0:
                    outf.write(b'\t')
                outf.write(b'0x' + '{:02x}'.format(data[n]).encode('utf-8')
                           + b',')
                i = i + 1
                if i % 8 == 0 or i == load_size:
                    outf.write(b'\n')
                else:
                    outf.write(b' ')
    outf.write(b'};\n')

    outf.write(b'const unsigned int ldelf_code_size = %d;\n' % code_size)
    outf.write(b'const unsigned int ldelf_data_size = %d;\n' % data_size)


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--input',
                        required=True, type=argparse.FileType('rb'),
                        help='The input ldelf.elf')

    parser.add_argument('--output',
                        required=True, type=argparse.FileType('wb'),
                        help='The output ldelf_hex.c')

    return parser.parse_args()


def main():
    args = get_args()
    inf = args.input
    outf = args.output

    elffile = ELFFile(inf)

    outf.write(b'/* Automatically generated, do no edit */\n')
    outf.write(b'#include <compiler.h>\n')
    outf.write(b'#include <stdint.h>\n')
    emit_load_segments(elffile, outf)
    outf.write(b'const unsigned long ldelf_entry = %lu;\n' %
               elffile.header['e_entry'])

    inf.close()
    outf.close()


if __name__ == "__main__":
    main()
