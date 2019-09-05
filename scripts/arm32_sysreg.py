#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Linaro Limited
#


import argparse
import sys
import re


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def my_err(line_number, msg):
    eprint('Error: line:' + repr(line_number) + ' ' + msg)
    sys.exit(1)


def gen_read64_macro(reg_name, opc1, crm, descr):
    print('')
    if len(descr):
        print('\t# ' + descr)
    print('\t.macro read_' + reg_name.lower() + ' reg0, reg1')
    print('\tmrrc\tp15, ' + opc1 + ', \\reg0, \\reg1, ' + crm)
    print('\t.endm')


def gen_write64_macro(reg_name, opc1, crm, descr):
    print('')
    if len(descr):
        print('\t# ' + descr)
    print('\t.macro write_' + reg_name.lower() + ' reg0, reg1')
    print('\tmcrr\tp15, ' + opc1 + ', \\reg0, \\reg1, ' + crm)
    print('\t.endm')


def gen_read32_macro(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('\t# ' + descr)
    print('\t.macro read_' + reg_name.lower() + ' reg')
    print('\tmrc p15, ' + opc1 + ', \\reg, ' + crn + ', ' + crm + ', ' + opc2)
    print('\t.endm')


def gen_write32_macro(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('\t# ' + descr)
    print('\t.macro write_' + reg_name.lower() + ' reg')
    print('\tmcr p15, ' + opc1 + ', \\reg, ' + crn + ', ' + crm + ', ' + opc2)
    print('\t.endm')


def gen_write32_dummy_macro(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('\t# ' + descr)
    print('\t.macro write_' + reg_name.lower())
    print('\t# Register ignored')
    print('\tmcr p15, ' + opc1 + ', r0, ' + crn + ', ' + crm + ', ' + opc2)
    print('\t.endm')


def gen_read64_func(reg_name, opc1, crm, descr):
    print('')
    if len(descr):
        print('/* ' + descr + ' */')
    print('static inline __noprof uint64_t read_' + reg_name.lower() +
          '(void)')
    print('{')
    print('\tuint64_t v;')
    print('')
    print('\tasm volatile ("mrrc p15, ' + opc1 + ', %Q0, %R0, ' +
          crm + '"' + ' : "=r"  (v));')
    print('')
    print('\treturn v;')
    print('}')


def gen_write64_func(reg_name, opc1, crm, descr):
    print('')
    if len(descr):
        print('/* ' + descr + ' */')
    print('static inline __noprof void write_' + reg_name.lower() +
          '(uint64_t v)')
    print('{')
    print('\tasm volatile ("mcrr p15, ' + opc1 + ', %Q0, %R0, ' +
          crm + '"' + ' : : "r"  (v));')
    print('}')


def gen_read32_func(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('/* ' + descr + ' */')
    print('static inline __noprof uint32_t read_' + reg_name.lower() +
          '(void)')
    print('{')
    print('\tuint32_t v;')
    print('')
    print('\tasm volatile ("mrc p15, ' + opc1 + ', %0, ' + crn + ', ' +
          crm + ', ' + opc2 + '"' + ' : "=r"  (v));')
    print('')
    print('\treturn v;')
    print('}')


def gen_write32_func(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('/* ' + descr + ' */')
    print('static inline __noprof void write_' + reg_name.lower() +
          '(uint32_t v)')
    print('{')
    print('\tasm volatile ("mcr p15, ' + opc1 + ', %0, ' + crn + ', ' +
          crm + ', ' + opc2 + '"' + ' : : "r"  (v));')
    print('}')


def gen_write32_dummy_func(reg_name, crn, opc1, crm, opc2, descr):
    print('')
    if len(descr):
        print('/* ' + descr + ' */')
    print('static inline __noprof void write_' + reg_name.lower() + '(void)')
    print('{')
    print('\t/* Register ignored */')
    print('\tasm volatile ("mcr p15, ' + opc1 + ', r0, ' + crn + ', ' +
          crm + ', ' + opc2 + '");')
    print('}')


def gen_file(line, line_number, s_file):
    words = line.split()
    if len(words) == 0:
        return

    if len(re.findall('^ *#', line)):
        return

    if len(re.findall('^ *@', line)):
        comment = re.sub('^ *@', '', line)
        comment = re.sub('^ *', '', comment)
        comment = re.sub('[ \n]*$', '', comment)
        if len(comment) == 0:
            print('')
            return
        if s_file:
            print('# ' + comment)
        else:
            print('/* ' + comment + ' */')
        return

    reg_name = words[0]
    crn = words[1]
    opc1 = words[2]
    crm = words[3]
    opc2 = words[4]
    access_type = words[5]
    descr = " ".join(words[6:])

    read_access = access_type == 'RO' or access_type == 'RW'
    write_access = (access_type == 'WO' or access_type == 'RW' or
                    access_type == 'WOD')
    dummy_access = access_type == 'WOD'

    if not read_access and not write_access:
        my_err(line_number, 'bad Access Type "' + access_type + '"')

    if crn == '-':
        if opc2 != '-':
            my_err(line_number, 'bad opc2, expected -')

        if read_access:
            if s_file:
                gen_read64_macro(reg_name, opc1, crm, descr)
            else:
                gen_read64_func(reg_name, opc1, crm, descr)

        if s_file:
            gen_write64_macro(reg_name, opc1, crm, descr)
        else:
            gen_write64_func(reg_name, opc1, crm, descr)
    else:
        if read_access:
            if s_file:
                gen_read32_macro(reg_name, crn, opc1, crm, opc2, descr)
            else:
                gen_read32_func(reg_name, crn, opc1, crm, opc2, descr)

        if write_access:
            if dummy_access:
                if s_file:
                    gen_write32_dummy_macro(reg_name, crn, opc1, crm, opc2,
                                            descr)
                else:
                    gen_write32_dummy_func(reg_name, crn, opc1, crm, opc2,
                                           descr)
            else:
                if s_file:
                    gen_write32_macro(reg_name, crn, opc1, crm, opc2, descr)
                else:
                    gen_write32_func(reg_name, crn, opc1, crm, opc2, descr)


def get_args():
    parser = argparse.ArgumentParser(description='Generates instructions to '
                                     'access ARM32 system registers.')

    parser.add_argument('--s_file', action='store_true',
                        help='Generate an Assembly instead of a C file')
    parser.add_argument('--guard',
                        help='Provide #ifdef <guard_argument> in C file')

    return parser.parse_args()


def main():
    args = get_args()

    cmnt = 'Automatically generated, do not edit'
    if args.s_file:
        print('# ' + cmnt)
    else:
        print('/* ' + cmnt + ' */')
        if args.guard is not None:
            print('#ifndef ' + args.guard.upper().replace('.', '_'))
            print('#define ' + args.guard.upper().replace('.', '_'))
        print('#include <compiler.h>')

    line_number = 0
    for line in sys.stdin:
        line_number = line_number + 1
        gen_file(line, line_number, args.s_file)

    if not args.s_file and args.guard is not None:
        print('#endif /*' + args.guard.upper().replace('.', '_') + '*/')


if __name__ == '__main__':
    main()
