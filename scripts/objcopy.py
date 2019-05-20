#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Linaro Limited

# Note: Ubuntu package: python-pyelftools
from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile
import re
import sys


def get_args():
    parser = ArgumentParser()
    parser.add_argument('-O', '--output-target', required='True',
                        help='Output format. Must be "binary".')
    parser.add_argument('-R', '--remove-section', action='append', default=[],
                        help='Remove section REMOVE_SECTION from the output.')
    parser.add_argument('-j', '--only-section', action='append', default=[],
                        help='Only copy section ONLY_SECTION into the output.')
    parser.add_argument('--pad-to',
                        help='Pad the last section up to address PAD_TO.')
    parser.add_argument('files', type=str, nargs='+',
                        help='Input file and (optionally) output file. '
                        'If no output file is specified, the input file is '
                        'replaced.')

    args = parser.parse_args()

    if args.output_target != 'binary':
        parser.print_usage()
        sys.exit(1)

    return args


def name_matches(name, patterns):
    for pattern in patterns:
        if re.match(pattern, name):
            return True
    return False


def main():
    loadable_segs = []

    args = get_args()

    if len(args.files) == 2:
        out = args.files[1]
    else:
        out = args.files[0]

    elffile = ELFFile(open(args.files[0], 'rb'))
    outfile = open(out, 'wb')

    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            loadable_segs.append(segment)

    keep_types = ['SHT_ARM_EXIDX', 'SHT_PROGBITS', 'SHT_REL', 'SHT_RELA']
    addr = 0
    pad = 0
    for section in elffile.iter_sections():
        if section.name.startswith('.debug'):
            continue
        if section['sh_type'] not in keep_types:
            continue
        if args.only_section:
            if not name_matches(section.name, args.only_section):
                continue
        else:
            if name_matches(section.name, args.remove_section):
                continue
        for segment in loadable_segs:
            if segment.section_in_segment(section):
                # Loadable section of the proper type and name: keep it
                if addr == 0:
                    addr = section['sh_addr']
                else:
                    pad = section['sh_addr'] - addr
                    if pad < 0:
                        print 'Sections not in ascending order!'
                        sys.exit(1)
                    for i in range(pad):
                        outfile.write('\0')
                    addr += pad
                outfile.write(section.data())
                addr += section['sh_size']
    if args.pad_to:
        pad = int(args.pad_to, 0) - addr
        if pad < 0:
            print 'Invalid value for --pad-to'
            sys.exit(1)
        for i in range(pad):
            outfile.write('\0')
        addr += pad
    outfile.close()


if __name__ == "__main__":
    main()
