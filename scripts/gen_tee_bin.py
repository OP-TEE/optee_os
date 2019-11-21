#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Linaro Limited
#

from __future__ import print_function
from __future__ import division

import argparse
import sys
import struct
import re
import hashlib
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_FLAGS
    from elftools.elf.sections import SymbolTableSection

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

small_page_size = 4 * 1024
elffile_symbols = None
tee_pageable_bin = None
tee_pager_bin = None
tee_embdata_bin = None


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def round_up(n, m):
    if n == 0:
        return 0
    else:
        return (((n - 1) // m) + 1) * m


def get_arch_id(elffile):
    e_machine = elffile.header['e_machine']
    if e_machine == 'EM_ARM':
        return 0
    if e_machine == 'EM_AARCH64':
        return 1
    eprint('Unknown e_machine "%s"' % e_machine)
    sys.exit(1)


def get_symbol(elffile, name):
    global elffile_symbols
    if elffile_symbols is None:
        elffile_symbols = dict()
        symbol_tables = [s for s in elffile.iter_sections()
                         if isinstance(s, SymbolTableSection)]
        for section in symbol_tables:
            for symbol in section.iter_symbols():
                if symbol['st_info']['bind'] == 'STB_GLOBAL':
                    elffile_symbols[symbol.name] = symbol

    try:
        return elffile_symbols[name]
    except (KeyError):
        eprint("Cannot find symbol %s" % name)
        sys.exit(1)


def get_sections(elffile, pad_to, dump_names):
    last_end = 0
    bin_data = bytearray()

    for section in elffile.iter_sections():
        if (section['sh_type'] == 'SHT_NOBITS' or
                not (section['sh_flags'] & SH_FLAGS.SHF_ALLOC) or
                not dump_names.match(section.name)):
            continue

        if last_end == 0:
            bin_data = section.data()
        else:
            if section['sh_addr'] > last_end:
                bin_data += bytearray(section['sh_addr'] - last_end)
            bin_data += section.data()

        last_end = section['sh_addr'] + section['sh_size']

    if pad_to > last_end:
        bin_data += bytearray(pad_to - last_end)
        last_end = pad_to

    return bin_data


def get_pageable_bin(elffile):
    global tee_pageable_bin
    if tee_pageable_bin is None:
        pad_to = 0
        dump_names = re.compile(r'^\..*_(pageable|init)$')
        tee_pageable_bin = get_sections(elffile, pad_to, dump_names)
    return tee_pageable_bin


def get_pager_bin(elffile):
    global tee_pager_bin
    if tee_pager_bin is None:
        pad_to = get_symbol(elffile, '__data_end')['st_value']
        dump_names = re.compile(
            r'^\.(text|rodata|got|data|ARM\.exidx|ARM\.extab|rel|rela)$')
        tee_pager_bin = get_sections(elffile, pad_to, dump_names)

    return tee_pager_bin


def get_hashes_bin(elffile):
    pageable_bin = get_pageable_bin(elffile)
    if len(pageable_bin) % small_page_size != 0:
        eprint("pageable size not a multiple of 4K: "
               "{}".format(paged_area_size))
        sys.exit(1)

    data = bytearray()
    for n in range(0, len(pageable_bin), small_page_size):
        page = pageable_bin[n:n + small_page_size]
        data += hashlib.sha256(page).digest()

    return data


def get_embdata_bin(elffile):
    global tee_embdata_bin
    if tee_embdata_bin is None:
        hashes_bin = get_hashes_bin(elffile)

        num_entries = 1
        hash_offs = 2 * 4 + num_entries * (2 * 4)
        hash_pad = round_up(len(hashes_bin), 8) - len(hashes_bin)
        total_len = hash_offs + len(hashes_bin) + hash_pad

        tee_embdata_bin = struct.pack('<IIII', total_len, num_entries,
                                      hash_offs, len(hashes_bin))
        tee_embdata_bin += hashes_bin + bytearray(hash_pad)

    # The embedded data region is designed to be easy to extend when
    # needed, it's formatted as:
    # +--------------------------------------------------------+
    # | uint32_t: Length of entire area including this field   |
    # +--------------------------------------------------------+
    # | uint32_t: Number of entries "1"                        |
    # +--------------------------------------------------------+
    # | uint32_t: Offset of hashes from beginning of table     |
    # +--------------------------------------------------------+
    # | uint32_t: Length of hashes                             |
    # +--------------------------------------------------------+
    # | Data of hashes + eventual padding                      |
    # +--------------------------------------------------------+

    return tee_embdata_bin


def output_pager_bin(elffile, outf):
    outf.write(get_pager_bin(elffile))


def output_pageable_bin(elffile, outf):
    outf.write(get_pageable_bin(elffile))


def get_init_load_addr(elffile):
    init_load_addr = get_symbol(elffile, '_start')['st_value']
    init_load_addr_hi = init_load_addr >> 32
    init_load_addr_lo = init_load_addr & 0xffffffff
    return init_load_addr_hi, init_load_addr_lo


def output_header_v1(elffile, outf):
    arch_id = get_arch_id(elffile)
    pager_bin = get_pager_bin(elffile)
    pageable_bin = get_pageable_bin(elffile)
    embdata_bin = get_embdata_bin(elffile)
    init_load_addr = get_init_load_addr(elffile)
    init_bin_size = get_symbol(elffile, '__init_size')['st_value']
    pager_bin_size = len(pager_bin)
    paged_area_size = len(pageable_bin)

    init_mem_usage = (get_symbol(elffile, '__init_end')['st_value'] -
                      get_symbol(elffile, '__text_start')['st_value'] +
                      len(embdata_bin))

    init_size = (pager_bin_size + min(init_bin_size, paged_area_size) +
                 len(embdata_bin))
    paged_size = paged_area_size - min(init_bin_size, paged_area_size)

    magic = 0x4554504f  # 'OPTE'
    version = 1
    flags = 0
    outf.write(struct.pack('<IBBHIIIII', magic, version, arch_id, flags,
                           init_size, init_load_addr[0], init_load_addr[1],
                           init_mem_usage, paged_size))
    outf.write(pager_bin)
    outf.write(pageable_bin[:init_bin_size])
    outf.write(embdata_bin)
    outf.write(pageable_bin[init_bin_size:])


def output_header_v2(elffile, outf):
    arch_id = get_arch_id(elffile)
    init_load_addr = get_init_load_addr(elffile)
    init_bin_size = get_symbol(elffile, '__init_size')['st_value']
    pager_bin_size = len(get_pager_bin(elffile))
    paged_area_size = len(get_pageable_bin(elffile))
    embdata_bin_size = len(get_embdata_bin(elffile))

    init_size = (pager_bin_size + min(init_bin_size, paged_area_size) +
                 embdata_bin_size)
    paged_size = paged_area_size - min(init_bin_size, paged_area_size)

    magic = 0x4554504f  # 'OPTE'
    version = 2
    flags = 0
    nb_images = 1 if paged_size == 0 else 2
    outf.write(struct.pack('<IBBHI', magic, version, arch_id, flags,
                           nb_images))
    outf.write(struct.pack('<IIII', init_load_addr[0], init_load_addr[1],
                           0, init_size))
    if nb_images == 2:
        outf.write(struct.pack('<IIII', 0xffffffff, 0xffffffff, 1, paged_size))


def output_pager_v2(elffile, outf):
    init_bin_size = get_symbol(elffile, '__init_size')['st_value']
    pager_bin = get_pager_bin(elffile)
    pageable_bin = get_pageable_bin(elffile)
    embdata_bin = get_embdata_bin(elffile)

    outf.write(pager_bin)
    outf.write(pageable_bin[:init_bin_size])
    outf.write(embdata_bin)


def output_pageable_v2(elffile, outf):
    init_bin_size = get_symbol(elffile, '__init_size')['st_value']
    outf.write(get_pageable_bin(elffile)[init_bin_size:])


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--input',
                        required=True, type=argparse.FileType('rb'),
                        help='The input tee.elf')

    parser.add_argument('--out_tee_bin',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee.bin')

    parser.add_argument('--out_tee_pager_bin',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee_pager.bin')

    parser.add_argument('--out_tee_pageable_bin',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee_pageable.bin')

    parser.add_argument('--out_header_v2',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee_header_v2.bin')

    parser.add_argument('--out_pager_v2',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee_pager_v2.bin')

    parser.add_argument('--out_pageable_v2',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee_pageable_v2.bin')

    return parser.parse_args()


def main():
    args = get_args()

    elffile = ELFFile(args.input)

    if args.out_tee_bin:
        output_header_v1(elffile, args.out_tee_bin)

    if args.out_tee_pager_bin:
        output_pager_bin(elffile, args.out_tee_pager_bin)

    if args.out_tee_pageable_bin:
        output_pageable_bin(elffile, args.out_tee_pageable_bin)

    if args.out_header_v2:
        output_header_v2(elffile, args.out_header_v2)

    if args.out_pager_v2:
        output_pager_v2(elffile, args.out_pager_v2)

    if args.out_pageable_v2:
        output_pageable_v2(elffile, args.out_pageable_v2)


if __name__ == "__main__":
    main()
