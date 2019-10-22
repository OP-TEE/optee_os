#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Huawei Technologies Co., Ltd

import argparse
import configparser
import os
import sys
import uuid


def get_args():
    parser = argparse.ArgumentParser(
        description='Generates a C source file from a text file defining the '
                    'dynamic library loading policy for user TAs')
    parser.add_argument('input', nargs='?', help='Input text file')
    parser.add_argument('-o', '--output', help='Output C file')
    return parser.parse_args()


def uuid_to_c(uuid_s):
    if uuid_s == '*':
        return 'ANY_UUID'
    u = uuid.UUID(uuid_s)
    s = (f'{{ 0x{u.time_low:08x}, 0x{u.time_mid:04x}, '
         f'0x{u.time_hi_version:04x}, {{ ')
    csn = f'{u.clock_seq_hi_variant:02x}{u.clock_seq_low:02x}{u.node:012x}'
    s += ', '.join('0x' + csn[i:i + 2] for i in range(0, len(csn), 2))
    s += ' } }'
    return s


def main():
    args = get_args()

    inf = sys.stdin
    if args.input:
        inf = open(args.input, 'r')
    else:
        args.input = '(stdin)'

    config = configparser.ConfigParser(inline_comment_prefixes=';')
    config.read_file(inf)

    policies = {}
    num = 0
    for section in config.sections():
        allowed_c = []
        allowed = config[section]['allowed']
        for a in allowed.split(','):
            a = a.strip()
            if a == '':
                continue
            allowed_c.append(uuid_to_c(a))
        allowed_c.append('{ }')
        if allowed not in policies:
            num = num + 1
            policies[allowed] = {'C': allowed_c, 'varname': f'policy{num}'}

    outf = sys.stdout
    if args.output:
        outf = open(args.output, 'w')
    outf.write('/* Generated from ' + args.input + ' by '
               + os.path.basename(__file__) + ' */\n')
    outf.write('#include <dl_policy.h>\n#include <tee_api_types.h>\n\n')

    for pol in policies:
        varname = policies[pol]["varname"]
        outf.write(f'static const TEE_UUID {varname}[] = {{ ')
        outf.write(', '.join(policies[pol]['C']))
        outf.write(' };\n')

    outf.write('\nstruct dl_policy dl_policies[] = {\n')
    for section in config.sections():
        if section == '*':
            uuid_c = 'ANY_UUID'
        else:
            uuid_c = uuid_to_c(section)
        allowed = config[section]['allowed']
        varname = policies[allowed]['varname']
        outf.write(f'\t{{ {uuid_c}, {varname} }},\n')
    outf.write('\t{ }\n};\n')
    outf.close()


if __name__ == "__main__":
    main()
