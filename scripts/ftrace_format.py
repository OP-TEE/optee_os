#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023, Linaro Limited
#
# Converts a ftrace binary file to text. The input file has the following
# format:
#
#  <ASCII text> <zero or more nul bytes> FTRACE\x00\x01 <binary data>...
#
# <binary data> is an array of 64-bit integers.
# - When the topmost byte is 0, the entry indicates a function return and the
# remaining bytes are a duration in nanoseconds.
# - A non-zero value is a stack depth, indicating a function entry, and the
# remaining bytes are the function's address.

import sys


line = ""
curr_depth = 0


def usage():
    print(f"Usage: {sys.argv[0]} ftrace.out")
    print("Converts a ftrace file to text. Output is written to stdout.")
    sys.exit(0)


def format_time(ns):
    if ns < 1000000:
        us = ns / 1000
        return f"{us:7.3f} us"
    else:
        ms = ns / 1000000
        return f"{ms:7.3f} ms"


def display(depth, val):
    global line, curr_depth
    if depth != 0:
        curr_depth = depth
        if line != "":
            line = line.replace("TIME", " " * 10) + " {"
            print(line)
            line = ""
        line = f" TIME | {depth:3} | " + " " * depth + f"0x{val:016x}()"
    else:
        if line != "":
            line = line.replace("TIME", format_time(val))
            print(line)
            line = ""
        else:
            if curr_depth != 0:
                curr_depth = curr_depth - 1
                print(" " + format_time(val) + f" | {curr_depth:3} | " +
                      " " * curr_depth + "}")


def main():
    if len(sys.argv) < 2:
        usage()
    with open(sys.argv[1], 'rb') as f:
        s = f.read()
    magic = s.find(b'FTRACE\x00\x01')
    if magic == -1:
        print("Magic not found", file=sys.stderr)
        sys.exit(1)
    print(s[:magic].rstrip(b'\x00').decode())
    s = s[magic + 8:]
    for i in range(0, len(s), 8):
        elem = int.from_bytes(s[i:i + 8], byteorder="little", signed=False)
        depth = elem >> 56
        val = elem & 0xFFFFFFFFFFFFFF
        display(depth, val)


if __name__ == "__main__":
    main()
