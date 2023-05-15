#!/usr/bin/env python3
#
# Copyright (c) 2014-2017, Linaro Limited
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import subprocess
import sys


def get_args():
    parser = argparse.ArgumentParser(description='Shows the memory usage '
                                     'of an OP-TEE based on ELF sections')
    parser.add_argument('tee_elf', help='the OP-TEE ELF file (tee.elf)')
    parser.add_argument('-a', '--all', action='store_true',
                        help=' same as -i -p -u -U')
    parser.add_argument('-n', '--no-map', action='store_true',
                        help=' do not show the detailed section mappings and '
                        'RAM usage')
    parser.add_argument('-i', '--init', action='store_true',
                        help='report the total size of the .*_init sections')
    parser.add_argument('-p', '--paged', action='store_true',
                        help='report the total size of the .*_pageable '
                        'sections')
    parser.add_argument('-u', '--unpaged', action='store_true',
                        help='report the total size of the unpaged sections, '
                        'that is, all sections but the ones in --init or '
                        '--paged')
    parser.add_argument('-U', '--unpaged-no-heap', action='store_true',
                        help='report the size of all unpaged sections '
                        'excluding heap space. Reflects the size of unpaged '
                        'code and data (.text, .rodata, .data, .bss, .nozi '
                        'and possibly unwind tables)')
    parser.add_argument('-r', '--raw', action='store_true',
                        help='when processing -i, -p, -u, or -U, show only '
                        'the size (in decimal) and no other text')
    return parser.parse_args()


def printf(format, *args):
    sys.stdout.write(format % args)


def print_sect(name, addr, size, round_up=False, print_num_pages=False):
    if args.no_map:
        return
    if size == 0:
        size_kib = 0
        num_pages = 0
    else:
        if round_up:
            size_kib = (size - 1) / 1024 + 1
        else:
            size_kib = size / 1024
        num_pages = (size - 1) / 4096 + 1

    printf('%-16s %.8X - %.8X size %.8X %3d KiB', name, addr, addr + size,
           size, size_kib)
    if print_num_pages:
        printf(' %d pages', num_pages)
    printf('\n')


def print_pager_stat(name, size):
    size_kib = size / 1024
    if args.raw:
        printf('%d ', size)
    else:
        printf('%-36s size %.8X %3d KiB\n', name, size, size_kib)


def readelf_cmd():
    return os.getenv('CROSS_COMPILE', '') + 'readelf'


def main():
    global args

    in_shdr = False
    sects = []
    init_size = 0
    paged_size = 0
    unpaged_size = 0
    unpaged_no_heap_size = 0

    args = get_args()
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    readelf = subprocess.Popen(str.split(readelf_cmd()) + ['-s',
                                                           args.tee_elf],
                               stdout=subprocess.PIPE, env=env,
                               universal_newlines=True)
    for line in iter(readelf.stdout.readline, ''):
        words = line.split()
        if len(words) == 8 and words[7] == '_end_of_ram':
            end_of_ram = int(words[1], 16)
            break
    readelf.terminate()
    readelf = subprocess.Popen(str.split(readelf_cmd()) + ['-S', '-W',
                                                           args.tee_elf],
                               stdout=subprocess.PIPE, env=env,
                               universal_newlines=True)
    for line in iter(readelf.stdout.readline, ''):
        if 'Section Headers:' in line:
            in_shdr = True
            continue
        if 'Key to Flags:' in line:
            in_shdr = False
            continue
        if in_shdr:
            words = line.split()
            if words[0] == '[':
                words.pop(0)
            try:
                (_, name, _, addr, offs, size, _,
                 flags) = words[:8]
            except BaseException:
                continue
            if ('A' in flags):
                sects.append({'name': name, 'addr': addr,
                              'offs': offs, 'size': size})
    first_addr = None
    for sect in sects:
        if sect['addr'] != 0:
            addr = sect['addr']
            if not first_addr:
                first_addr = addr
            if int(addr, 16) >= end_of_ram:
                break
            last_addr = addr
            last_size = sect['size']

    ram_usage = int(last_addr, 16) + int(last_size, 16) - int(first_addr, 16)
    print_sect('RAM Usage', int(first_addr, 16), ram_usage, True, True)

    last_addr = 0
    last_size = 0
    for sect in sects:
        name = sect['name']
        addr = int(sect['addr'], 16)
        size = int(sect['size'], 16)

        if addr >= end_of_ram:
            break
        if last_addr != 0 and addr != last_addr + last_size:
            print_sect('*hole*', last_addr + last_size,
                       addr - (last_addr + last_size))
        print_sect(name, addr, size)
        if name.endswith('_init'):
            init_size += size
        elif name.endswith('_pageable'):
            paged_size += size
        else:
            if not name.startswith('.heap'):
                unpaged_no_heap_size += size
            unpaged_size += size
        last_addr = addr
        last_size = size

    if args.all or args.init:
        print_pager_stat('Init sections (.*_init)', init_size)
    if args.all or args.paged:
        print_pager_stat('Paged sections (.*_pageable)', paged_size)
    if args.all or args.unpaged:
        print_pager_stat('Unpaged sections ', unpaged_size)
    if args.all or args.unpaged_no_heap:
        print_pager_stat('Unpaged sections (heap excluded)',
                         unpaged_no_heap_size)
    if (args.raw and (args.all or args.init or args.paged or
                      args.unpaged or args.unpaged_no_heap)):
        printf('\n')


if __name__ == "__main__":
    main()
