#!/usr/bin/env python3
#
# Copyright (c) 2014-2017, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import subprocess
import sys


def get_args():
    parser = argparse.ArgumentParser(
        description='Shows the memory layout of the TEE ELF file. '
        'Size is provided for each section.')
    parser.add_argument('tee_elf', help='The OP-TEE ELF file (tee.elf)')
    return parser.parse_args()


def printf(format, *args):
    sys.stdout.write(format % args)


def print_sect(name, addr, size, round_up=False, print_num_pages=False):
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


def readelf_cmd():
    return os.getenv('CROSS_COMPILE', '') + 'readelf'


def main():
    in_shdr = False
    sects = []

    args = get_args()
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    readelf = subprocess.Popen([readelf_cmd(), '-S', '-W', args.tee_elf],
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
            except:
                continue
            if (flags == 'AX' or flags == 'WA' or flags == 'A' or
                    flags == 'AL'):
                sects.append({'name': name, 'addr': addr,
                              'offs': offs, 'size': size})
    for sect in sects:
        if sect['addr'] != 0:
            first_addr = sect['addr']
            break
    last_addr = sects[-1]['addr']
    last_size = sects[-1]['size']

    ram_usage = int(last_addr, 16) + int(last_size, 16) - int(first_addr, 16)
    print_sect('RAM Usage', int(first_addr, 16), ram_usage, True, True)

    last_addr = 0
    last_size = 0
    for sect in sects:
        name = sect['name']
        addr = int(sect['addr'], 16)
        size = int(sect['size'], 16)

        if last_addr != 0 and addr != last_addr + last_size:
            print_sect('*hole*', last_addr + last_size,
                       addr - (last_addr + last_size))
        print_sect(name, addr, size)
        last_addr = addr
        last_size = size


if __name__ == "__main__":
    main()
