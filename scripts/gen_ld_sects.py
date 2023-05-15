#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017, Linaro Limited
#

import sys
import re


def usage():
    print("Usage: {0} <section reg exp match> [<skip section>...]".format(
        sys.argv[0]))
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        usage()

    in_shdr = False
    section_headers = re.compile("Section Headers:")
    key_to_flags = re.compile("Key to Flags:")
    match_rule = re.compile(sys.argv[1])
    skip_sections = sys.argv[2:]

    for line in sys.stdin:
        if section_headers.match(line):
            in_shdr = True
            continue
        if key_to_flags.match(line):
            in_shdr = False
            continue

        if not in_shdr:
            continue

        words = line.split()

        if len(words) < 3:
            continue

        if words[0] == "[":
            name_offs = 2
        else:
            name_offs = 1

        sect_name = words[name_offs]
        sect_type = words[name_offs + 1]

        if sect_type != "PROGBITS":
            continue

        if not match_rule.match(sect_name):
            continue

        if sect_name in skip_sections:
            continue

        print('\t*({0})'.format(sect_name))


if __name__ == "__main__":
    main()
