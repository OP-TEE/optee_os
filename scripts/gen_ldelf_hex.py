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


def round_up(n, m):
    if n == 0:
        return 0
    else:
        return (((n - 1) // m) + 1) * m


def emit_load_segments(elffile, outf):
    load_size = 0
    code_size = 0
    data_size = 0
    load_segments = [s for s in elffile.iter_segments()
                     if s['p_type'] == 'PT_LOAD']
    prev_segment = None
    pad = 0
    pad_size = []
    w_found = False
    n = 0
    # Check that load segments ordered by VA have the expected layout:
    # read only first, then read-write. Compute padding at end of each segment,
    # 0 if none is required.
    for segment in load_segments:
        if prev_segment:
            pad = segment['p_vaddr'] - (prev_segment['p_vaddr'] +
                                        prev_segment['p_filesz'])
        else:
            if segment['p_flags'] & P_FLAGS.PF_W:
                print('Expected RO load segment(s) first')
                sys.exit(1)
        if segment['p_flags'] & P_FLAGS.PF_W:
            if not w_found:
                # End of RO segments, discard padding for the last one (it
                # would just take up space in the generated C file)
                pad = 0
                w_found = True
        else:
            if w_found:
                print('RO load segment found after RW one(s) (m={})'.format(n))
                sys.exit(1)
        if prev_segment:
            if pad > 31:
                # We expect segments to be tightly packed together for memory
                # efficiency. 31 is an arbitrary, "sounds reasonable" value
                # which might need to be adjusted -- who knows what the
                # compiler/linker can do.
                print('Warning: suspiciously large padding ({}) after load '
                      'segment {}, please check'.format(pad, n-1))
            pad_size.append(pad)
        prev_segment = segment
        n = n + 1
    pad_size.append(0)
    n = 0
    # Compute code_size, data_size and load_size
    for segment in load_segments:
        sz = segment['p_filesz'] + pad_size[n]
        if segment['p_flags'] & P_FLAGS.PF_W:
            data_size += sz
        else:
            code_size += sz
        load_size += sz
        n = n + 1
    n = 0
    i = 0
    # Output data to C file
    outf.write(b'const uint8_t ldelf_data[%d]' % round_up(load_size, 4096))
    outf.write(b' __aligned(4096) = {\n')
    for segment in load_segments:
        data = segment.data()
        if pad_size[n]:
            # Pad with zeros if needed
            data += bytearray(pad_size[n])
        for j in range(len(data)):
            if i % 8 == 0:
                outf.write(b'\t')
            outf.write(b'0x' + '{:02x}'.format(data[j]).encode('utf-8')
                       + b',')
            i = i + 1
            if i % 8 == 0 or i == load_size:
                outf.write(b'\n')
            else:
                outf.write(b' ')
        n = n + 1
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
