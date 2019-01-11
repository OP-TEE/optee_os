#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2014-2017, Linaro Limited
#

import argparse
import sys
import shutil
import os
import struct
import hashlib

arch_id = {'arm32': 0, 'arm64': 1}
image_id = {'pager': 0, 'paged': 1}


def write_header_v1(outf, init_size, args, paged_size):
    magic = 0x4554504f  # 'OPTE'
    version = 1
    outf.write(struct.pack('<IBBHIIIII',
                           magic,
                           version,
                           arch_id[args.arch],
                           args.flags,
                           init_size,
                           args.init_load_addr_hi,
                           args.init_load_addr_lo,
                           args.init_mem_usage,
                           paged_size))


def write_header_v2(outf, init_size, args, paged_size):
    magic = 0x4554504f  # 'OPTE'
    version = 2
    nb_images = 1 if paged_size == 0 else 2
    outf.write(struct.pack('<IBBHI', magic, version,
                           arch_id[args.arch], args.flags, nb_images))
    outf.write(struct.pack('<IIII',
                           args.init_load_addr_hi, args.init_load_addr_lo,
                           image_id['pager'], init_size))
    if nb_images == 2:
        outf.write(
            struct.pack(
                '<IIII',
                0xffffffff,
                0xffffffff,
                image_id['paged'],
                paged_size))


def append_to(outf, start_offs, in_fname, max_bytes=0xffffffff):
    inf = open(in_fname, 'rb')
    inf.seek(start_offs)
    while True:
        nbytes = min(16 * 1024, max_bytes)
        if nbytes == 0:
            break
        buf = inf.read(nbytes)
        if not buf:
            break
        outf.write(buf)
        max_bytes -= len(buf)
    inf.close()


def append_hashes(outf, in_fname):
    page_size = 4 * 1024

    inf = open(in_fname, 'rb')
    while True:
        page = inf.read(page_size)
        if len(page) == page_size:
            outf.write(hashlib.sha256(page).digest())
        elif len(page) == 0:
            break
        else:
            print("Error: short read, got " + repr(len(page)))
            sys.exit(1)

    inf.close()


def int_parse(str):
    return int(str, 0)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', required=True,
                        choices=arch_id.keys(),
                        help='Architecture')

    parser.add_argument('--flags',
                        type=int, default=0,
                        help='Flags, currently none defined')

    parser.add_argument('--init_size',
                        required=True, type=int_parse,
                        help='Size of initialization part of binary')

    parser.add_argument('--init_load_addr_hi',
                        type=int_parse, default=0,
                        help='Upper 32 bits of load address of binary')

    parser.add_argument('--init_load_addr_lo',
                        required=True, type=int_parse,
                        help='Lower 32 bits of load address of binary')

    parser.add_argument('--init_mem_usage',
                        required=True, type=int_parse,
                        help='Total amount of used memory when initializing')

    parser.add_argument('--tee_pager_bin',
                        required=True,
                        help='The input tee_pager.bin')

    parser.add_argument('--tee_pageable_bin',
                        required=True,
                        help='The input tee_pageable.bin')

    parser.add_argument('--out',
                        required=False, type=argparse.FileType('wb'),
                        help='The output tee.bin')

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
    init_bin_size = args.init_size
    tee_pager_fname = args.tee_pager_bin
    tee_pageable_fname = args.tee_pageable_bin
    pager_input_size = os.path.getsize(tee_pager_fname)
    paged_input_size = os.path.getsize(tee_pageable_fname)
    hash_size = paged_input_size // (4 * 1024) * \
        hashlib.sha256().digest_size

    if paged_input_size % (4 * 1024) != 0:
        print("Error: pageable size not a multiple of 4K:" +
              repr(paged_input_size))
        sys.exit(1)

    init_size = pager_input_size + \
        min(init_bin_size, paged_input_size) + \
        hash_size
    paged_size = paged_input_size - \
        min(init_bin_size, paged_input_size)

    if args.out is not None:
        outf = args.out
        write_header_v1(outf, init_size, args, paged_size)
        append_to(outf, 0, tee_pager_fname)
        append_to(outf, 0, tee_pageable_fname, init_bin_size)
        append_hashes(outf, tee_pageable_fname)
        append_to(outf, init_bin_size, tee_pageable_fname)
        outf.close()

    if args.out_header_v2 is not None:
        outf = args.out_header_v2
        write_header_v2(outf, init_size, args, paged_size)
        outf.close()

    if args.out_pager_v2 is not None:
        outf = args.out_pager_v2
        append_to(outf, 0, tee_pager_fname)
        append_to(outf, 0, tee_pageable_fname, init_bin_size)
        append_hashes(outf, tee_pageable_fname)
        outf.close()

    if args.out_pageable_v2 is not None:
        outf = args.out_pageable_v2
        append_to(outf, init_bin_size, tee_pageable_fname)
        outf.close()


if __name__ == "__main__":
    main()
