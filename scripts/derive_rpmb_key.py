#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023, Linaro Limited
#

import sys


def hex_parse(str):
    try:
        h = bytes.fromhex(str)
    except ValueError as e:
        try:
            # Try to pad with a '0' nibble in front
            h = bytes.fromhex('0' + str)
            print('Odd number of nibbles in hexadecimal string',
                  file=sys.stderr)
            raise e
        except ValueError:
            raise e
    return h


def get_args():
    import argparse
    import textwrap

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description='''Derive an RPMB key from the Hardware Unique Key used
                       by OP-TEE and the CID of the RPMB.''',
        epilog='''Note that the derived key matches what the
                  __huk_subkey_derive() would produce. If huk_subkey_derive()
                  is overridden to call another function, please don't use
                  this script''')

    parser.add_argument('--quiet', action='store_true', default=False,
                        help='''Gives only the hexstring of the RPMB key as
                                output, intended for scripting''')
    parser.add_argument('--testkey', action='store_true', default=False,
                        help='''Outputs the hardcoded test key''')
    parser.add_argument('--huk', type=hex_parse,
                        help='''Hardware Unique Key (16 bytes), as returned
                                by the platform specific function
                                tee_otp_get_hw_unique_key() in OP-TEE''')
    parser.add_argument('--cid', type=hex_parse, help='CID (16 bytes)')
    parser.add_argument('--compat', action='store_true', default=False,
                        help='''Generates a backwards compatible key,
                                only to be used if OP-TEE is build with
                                CFG_CORE_HUK_SUBKEY_COMPAT=y''')

    return parser.parse_args()


def derive_key(huk, cid, compat):
    import struct
    from cryptography.hazmat.primitives import hashes, hmac

    # Prepare the CID and Clear the PRV (Product revision) and CRC (CRC7
    # checksum) fields as OP-TEE does.
    data = bytearray(cid)
    data[9] = 0
    data[15] = 0

    # This is how __huk_subkey_derive() is implemented, if huk_subkey_derive()
    # is overridden the key derived here may not match what OP-TEE is using
    #
    # HUK is as tee_otp_get_hw_unique_key() in OP-TEE returns it
    h = hmac.HMAC(huk, hashes.SHA256())
    if not compat:
        usage_word = struct.pack('<I', 0)
        h.update(usage_word)
    h.update(data)
    return h.finalize()


def main():
    args = get_args()

    if args.testkey:
        if args.cid or args.huk or args.compat:
            print('--cid, --huk, or --compat '
                  'cannot be given together with --testkey')
            sys.exit(1)
        # The test key hardcoded in OP-TEE
        key = bytes.fromhex('''D3 EB 3E C3 6E 33 4C 9F
                               98 8C E2 C0 B8 59 54 61
                               0D 2B CF 86 64 84 4D F2
                               AB 56 E6 C6 1B B7 01 E4''')
    else:
        if not args.cid:
            print('--cid is required without --testkey')
            sys.exit(1)

        if not args.huk:
            print('--huk is required without --testkey')
            sys.exit(1)

        if len(args.cid) != 16:
            print(f'Invalid CID length, expected 16 bytes got {len(args.cid)}',
                  file=sys.stderr)
            sys.exit(1)

        if len(args.huk) != 16:
            print(f'Invalid HUK length, expected 16 bytes got {len(args.huk)}',
                  file=sys.stderr)
            sys.exit(1)

        if not args.quiet:
            print(f'HUK:      {args.huk.hex()} length {len(args.huk)}')
            print(f'RPMB CID: {args.cid.hex()} length {len(args.cid)}')

        key = derive_key(args.huk, args.cid, args.compat)

    if args.quiet:
        print(key.hex())
    else:
        print(f'RPMB key: {key.hex()}')
        print(f'          length {len(key)}')
        if args.testkey:
            print('''
*********************************************************************
*** Please note that the test key should only be used for testing ***
*** purposes since it's well known and the same for all devices.  ***
*********************************************************************''')
        else:
            print('''
Please take care to double-check the provided input since writing the RPMB
key is an irreversible step.''')


if __name__ == "__main__":
    main()
