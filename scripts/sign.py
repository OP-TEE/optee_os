#!/usr/bin/env python
#
# Copyright (c) 2015, 2017, Linaro Limited
#
# SPDX-License-Identifier: BSD-2-Clause

import sys


def uuid_parse(s):
    from uuid import UUID
    return UUID(s)


def int_parse(str):
    return int(str, 0)


def get_args(logger):
    from argparse import ArgumentParser, RawDescriptionHelpFormatter
    import textwrap
    command_base = ['sign', 'digest', 'stitch']
    command_aliases_digest = ['generate-digest']
    command_aliases_stitch = ['stitch-ta']
    command_aliases = command_aliases_digest + command_aliases_stitch
    command_choices = command_base + command_aliases

    dat = '[' + ', '.join(command_aliases_digest) + ']'
    sat = '[' + ', '.join(command_aliases_stitch) + ']'

    parser = ArgumentParser(
        description='Sign a Tusted Application for OP-TEE.',
        usage='\n   %(prog)s command [ arguments ]\n\n'

        '   command:\n' +
        '     sign        Generate signed loadable TA image file.\n' +
        '                 Takes arguments --uuid, --ta-version, --in, --out' +
        ' and --key.\n' +
        '     digest      Generate loadable TA binary image digest' +
        ' for offline\n' +
        '                 signing. Takes arguments  --uuid, --ta-version,' +
        ' --in and --dig.\n' +
        '     stitch      Generate loadable signed TA binary image' +
        ' file from\n' +
        '                 TA raw image and its signature. Takes' +
        ' arguments\n' +
        '                 --uuid, --in, --out, and --sig.\n\n' +
        '   %(prog)s --help  show available commands and arguments\n\n',
        formatter_class=RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            If no command is given, the script will default to "sign".

            command aliases:
              The command \'digest\' can be aliased by ''' + dat + '''
              The command \'stitch\' can be aliased by ''' + sat + '\n' + '''
            example offline signing command using OpenSSL:
              base64 -d <UUID>.dig | \\
              openssl pkeyutl -sign -inkey <KEYFILE>.pem \\
                  -pkeyopt digest:sha256 \\
                  -pkeyopt rsa_padding_mode:pkcs1 | \\
              base64 > <UUID>.sig
            '''))

    parser.add_argument(
        'command', choices=command_choices, nargs='?',
        default='sign',
        help='Command, one of [' + ', '.join(command_base) + ']')
    parser.add_argument('--uuid', required=True,
                        type=uuid_parse, help='String UUID of the TA')
    parser.add_argument('--key', required=True,
                        help='Name of key file (PEM format)')
    parser.add_argument(
        '--ta-version', required=False, type=int_parse, default=0,
        help='TA version stored as a 32-bit unsigned integer and used for\n' +
        'rollback protection of TA install in the secure database.\n' +
        'Defaults to 0.')
    parser.add_argument(
        '--sig', required=False, dest='sigf',
        help='Name of signature input file, defaults to <UUID>.sig')
    parser.add_argument(
        '--dig', required=False, dest='digf',
        help='Name of digest output file, defaults to <UUID>.dig')
    parser.add_argument(
        '--in', required=False, dest='inf',
        help='Name of application input file, defaults to <UUID>.stripped.elf')
    parser.add_argument(
        '--out', required=False, dest='outf',
        help='Name of application output file, defaults to <UUID>.ta')

    parsed = parser.parse_args()

    # Check parameter combinations

    if parsed.digf is None and \
       parsed.outf is not None and \
       parsed.command in ['digest'] + command_aliases_digest:
        logger.error('A digest was requested, but argument --out was given.' +
                     '  Did you mean:\n  ' +
                     parser.prog+' --dig ' + parsed.outf + ' ...')
        sys.exit(1)

    if parsed.digf is not None \
       and parsed.outf is not None \
       and parsed.command in ['digest'] + command_aliases_digest:
        logger.warn('A digest was requested, but arguments --dig and ' +
                    '--out were given.\n' +
                    '  --out will be ignored.')

    # Set defaults for optional arguments.

    if parsed.sigf is None:
        parsed.sigf = str(parsed.uuid)+'.sig'
    if parsed.digf is None:
        parsed.digf = str(parsed.uuid)+'.dig'
    if parsed.inf is None:
        parsed.inf = str(parsed.uuid)+'.stripped.elf'
    if parsed.outf is None:
        parsed.outf = str(parsed.uuid)+'.ta'

    return parsed


def main():
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import ceil_div
    import base64
    import logging
    import os
    import struct

    logging.basicConfig()
    logger = logging.getLogger(os.path.basename(__file__))

    args = get_args(logger)

    with open(args.key, 'rb') as f:
        key = RSA.importKey(f.read())

    with open(args.inf, 'rb') as f:
        img = f.read()

    h = SHA256.new()

    digest_len = h.digest_size
    sig_len = ceil_div(key.size() + 1, 8)
    img_size = len(img)

    hdr_version = args.ta_version  # struct shdr_bootstrap_ta::ta_version

    magic = 0x4f545348   # SHDR_MAGIC
    img_type = 1         # SHDR_BOOTSTRAP_TA
    algo = 0x70004830    # TEE_ALG_RSASSA_PKCS1_V1_5_SHA256

    shdr = struct.pack('<IIIIHH',
                       magic, img_type, img_size, algo, digest_len, sig_len)
    shdr_uuid = args.uuid.bytes
    shdr_version = struct.pack('<I', hdr_version)

    h.update(shdr)
    h.update(shdr_uuid)
    h.update(shdr_version)
    h.update(img)
    img_digest = h.digest()

    def write_image_with_signature(sig):
        with open(args.outf, 'wb') as f:
            f.write(shdr)
            f.write(img_digest)
            f.write(sig)
            f.write(shdr_uuid)
            f.write(shdr_version)
            f.write(img)

    def sign_ta():
        if not key.has_private():
            logger.error('Provided key cannot be used for signing, ' +
                         'please use offline-signing mode.')
            sys.exit(1)
        else:
            signer = PKCS1_v1_5.new(key)
            sig = signer.sign(h)
            write_image_with_signature(sig)
            logger.info('Successfully signed application.')

    def generate_digest():
        with open(args.digf, 'wb+') as digfile:
            digfile.write(base64.b64encode(img_digest))

    def stitch_ta():
        try:
            with open(args.sigf, 'r') as sigfile:
                sig = base64.b64decode(sigfile.read())
        except IOError:
            if not os.path.exists(args.digf):
                generate_digest()
            logger.error('No signature file found. Please sign\n %s\n' +
                         'offline and place the signature at \n %s\n' +
                         'or pass a different location ' +
                         'using the --sig argument.\n',
                         args.digf, args.sigf)
            sys.exit(1)
        else:
            verifier = PKCS1_v1_5.new(key)
            if verifier.verify(h, sig):
                write_image_with_signature(sig)
                logger.info('Successfully applied signature.')
            else:
                logger.error('Verification failed, ignoring given signature.')
                sys.exit(1)

    # dispatch command
    {
        'sign': sign_ta,
        'digest': generate_digest,
        'generate-digest': generate_digest,
        'stitch': stitch_ta,
        'stitch-ta': stitch_ta
    }.get(args.command, 'sign_ta')()


if __name__ == "__main__":
    main()
