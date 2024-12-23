#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024, Telechips Inc.
#

import sys
from hashlib import sha256

ALIGN_SIZE = 64
FOOTER_SIZE = 128


def calc_hash(inputfile):
    sha = sha256()
    inputfile.seek(0)
    while True:
        buf = inputfile.read(ALIGN_SIZE)
        if len(buf) == 0:
            break
        sha.update(buf.ljust(ALIGN_SIZE, b'\0'))
    return sha.digest()


def fill_dummy_cert(outputfile):
    outputfile.write(b'CERT'.ljust(256, b'\0'))
    return 0


def fill_header(outputfile, inputfile, argv):
    imagename = bytes(argv[3], 'utf-8')
    imageversion = bytes(argv[4], 'utf-8')
    targetaddress = int(argv[5], 16)
    socname = bytes(argv[6], 'utf-8')
    inputfile.seek(0, 2)
    offset = 4096  # Min: 256
    length = (inputfile.tell() + (ALIGN_SIZE - 1)) & ~(ALIGN_SIZE - 1)
    length += FOOTER_SIZE
    buf = bytearray(offset - outputfile.tell())
    buf[0:4] = b'HDR\0'  # Marker
    buf[4:8] = length.to_bytes(4, byteorder='little')
    buf[8:12] = offset.to_bytes(4, byteorder='little')
    buf[16:20] = socname.ljust(4, b'\0')[-4:]
    buf[20:32] = imagename.ljust(12, b'\0')[0:12]
    buf[32:48] = imageversion.ljust(16, b'\0')[0:16]
    buf[48:56] = targetaddress.to_bytes(8, byteorder='little')
    buf[96:128] = calc_hash(inputfile)
    outputfile.write(buf)
    return 0


def fill_image(outputfile, inputfile):
    inputfile.seek(0)
    while True:
        buf = inputfile.read(ALIGN_SIZE)
        if len(buf) == 0:
            break
        outputfile.write(buf.ljust(ALIGN_SIZE, b'\0'))
    return 0


def fill_dummy_footer(outputfile):
    outputfile.write(bytearray(FOOTER_SIZE))
    return 0


def make_image(inputfile, outputfile, argv):
    if fill_dummy_cert(outputfile) != 0:
        return -1
    if fill_header(outputfile, inputfile, argv) != 0:
        return -2
    if fill_image(outputfile, inputfile) != 0:
        return -3
    if fill_dummy_footer(outputfile) != 0:
        return -4
    return 0


def print_help():
    print("")
    print("Telechips Image Maker")
    print("")
    print("Usage: python tcmktool.py [INPUT] [OUTPUT] [NAME] [VERSION]" +
          " [TARGET_ADDRESS] [SOC_NAME]")
    print("")
    print("  INPUT                  input file name.")
    print("  OUTPUT                 output file name.")
    print("  NAME                   image name.")
    print("  VERSION                string version. (max 16 bytes)")
    print("  TARGET_ADDRESS         target address")
    print("  SOC_NAME               SoC name. (only the last 4 bytes are used")


def main(argc, argv):
    ret = -1

    if argc != 7:
        print_help()
        return -1

    try:
        with open(argv[1], "rb") as inputfile:
            with open(argv[2], "wb") as outputfile:
                ret = make_image(inputfile, outputfile, argv)
    except Exception as e:
        if 'inputfile' not in locals():
            print("ERROR: input file open error\n")
        elif 'outputfile' not in locals():
            print("ERROR: output file open error\n")
        else:
            print(e)

    if ret == 0:
        print("{} was generated successfilly\n".format(argv[2]))
    else:
        print("Failed to generate output file (error code: {})\n".format(ret))

    return ret


if (__name__ == "__main__"):
    exit(main(len(sys.argv), sys.argv))
