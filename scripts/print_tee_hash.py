#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2021, Huawei Technologies Co., Ltd
#

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import codecs
import sys

verbose = False


def dump(buf):
    print(codecs.encode(buf, 'hex').decode('utf-8'))


def resolve_symbol(elf, name):
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol.name == name:
                    return symbol.entry['st_value']
    raise RuntimeError(f'Symbol {name} not found')


def hash_range(h, elf, start, end):
    global verbose
    start_addr = resolve_symbol(elf, start)
    end_addr = resolve_symbol(elf, end)
    size = end_addr - start_addr
    if verbose:
        print(f'[{start}(0x{start_addr:x}), {end}(0x{end_addr:x})]: '
              f'{size} bytes')
    for segment in elf.iter_segments():
        if (segment['p_type'] == 'PT_LOAD' and
                segment['p_vaddr'] <= start_addr and
                end_addr <= segment['p_vaddr'] + segment['p_filesz']):
            begin_offs = start_addr - segment['p_vaddr']
            h.update(segment.data()[begin_offs:begin_offs + size])


def hash_section(h, elf, name):
    global verbose
    s = elf.get_section_by_name(name)
    if s is None:
        return
    d = s.data()
    if verbose:
        print(f'{name}: {len(d)} bytes')
    h.update(d)


def main():
    global verbose
    argc = len(sys.argv)
    if argc != 2 and argc != 3:
        print('Usage:', sys.argv[0], '<tee.elf>')
        return 1

    if argc == 3 and sys.argv[1] == '-v':
        verbose = True

    with open(sys.argv[argc - 1], 'rb') as f:
        elf = ELFFile(f)
        h = hashes.Hash(hashes.SHA256(), default_backend())
        hash_range(h, elf, '__text_start', '__text_data_start')
        hash_range(h, elf, '__text_data_end', '__text_end')
        hash_section(h, elf, '.text_init')
        hash_section(h, elf, '.text_pageable')
        hash_section(h, elf, '.rodata')
        hash_section(h, elf, '.rodata_init')
        hash_section(h, elf, '.rodata_pageable')
        dump(h.finalize())


if __name__ == "__main__":
    main()
