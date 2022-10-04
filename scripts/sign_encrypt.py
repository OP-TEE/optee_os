#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2015, 2017, 2019, Linaro Limited
#

import sys
import math


algo = {'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256': 0x70414930,
        'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256': 0x70004830}

enc_key_type = {'SHDR_ENC_KEY_DEV_SPECIFIC': 0x0,
                'SHDR_ENC_KEY_CLASS_WIDE': 0x1}

SHDR_BOOTSTRAP_TA = 1
SHDR_ENCRYPTED_TA = 2
SHDR_MAGIC = 0x4f545348
SHDR_SIZE = 20


def uuid_parse(s):
    from uuid import UUID
    return UUID(s)


def int_parse(str):
    return int(str, 0)


def get_args():
    def arg_add_uuid(parser):
        parser.add_argument(
            '--uuid', required=True, type=uuid_parse,
            help='String UUID of the TA')

    def arg_add_key(parser):
        parser.add_argument(
            '--key', required=True, help='''
                Name of signing and verification key file (PEM format) or an
                Amazon Resource Name (arn:) of an AWS KMS asymmetric key.
                At least public key for the commands digest, stitch, and
                verify, else a private key''')

    def arg_add_enc_key(parser):
        parser.add_argument(
            '--enc-key', required=False, help='Encryption key string')

    def arg_add_enc_key_type(parser):
        parser.add_argument(
            '--enc-key-type', required=False,
            default='SHDR_ENC_KEY_DEV_SPECIFIC',
            choices=list(enc_key_type.keys()), help='''
                Encryption key type,
                Defaults to SHDR_ENC_KEY_DEV_SPECIFIC.''')

    def arg_add_ta_version(parser):
        parser.add_argument(
            '--ta-version', required=False, type=int_parse, default=0, help='''
                TA version stored as a 32-bit unsigned integer and used for
                rollback protection of TA install in the secure database.
                Defaults to 0.''')

    def arg_add_sig(parser):
        parser.add_argument(
            '--sig', required=True, dest='sigf',
            help='Name of signature input file, defaults to <UUID>.sig')

    def arg_add_dig(parser):
        parser.add_argument(
            '--dig', required=True, dest='digf',
            help='Name of digest output file, defaults to <UUID>.dig')

    def arg_add_in(parser):
        parser.add_argument(
            '--in', required=False, dest='inf', help='''
                Name of application input file, defaults to
                <UUID>.stripped.elf''')

    def arg_add_out(parser):
        parser.add_argument(
            '--out', required=True, dest='outf',
            help='Name of application output file, defaults to <UUID>.ta')

    def arg_add_algo(parser):
        parser.add_argument(
            '--algo', required=False, choices=list(algo.keys()),
            default='TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256', help='''
                The hash and signature algorithm.
                Defaults to TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256.''')

    def get_outf_default(parsed):
        return str(parsed.uuid) + '.ta'

    def get_inf_default(parsed):
        return str(parsed.uuid) + '.stripped.elf'

    def get_sigf_default(parsed):
        return str(parsed.uuid) + '.sig'

    def get_digf_default(parsed):
        return str(parsed.uuid) + '.dig'

    def assign_default_value(parsed, attr, func):
        if hasattr(parsed, attr) and getattr(parsed, attr) is None:
            setattr(parsed, attr, func(parsed))

    import argparse
    import textwrap

    parser = argparse.ArgumentParser(
        description='Sign and encrypt (optional) a Trusted Application ' +
        ' for OP-TEE.',
        usage='%(prog)s <command> ...',
        epilog='<command> -h for detailed help')
    subparsers = parser.add_subparsers(
            title='valid commands, with possible aliases in ()',
            dest='command', metavar='')

    parser_sign_enc = subparsers.add_parser(
        'sign-enc', prog=parser.prog + ' sign-enc',
        help='Generate signed and optionally encrypted loadable TA image file')
    arg_add_uuid(parser_sign_enc)
    arg_add_ta_version(parser_sign_enc)
    arg_add_in(parser_sign_enc)
    arg_add_out(parser_sign_enc)
    arg_add_key(parser_sign_enc)
    arg_add_enc_key(parser_sign_enc)
    arg_add_enc_key_type(parser_sign_enc)
    arg_add_algo(parser_sign_enc)

    parser_digest = subparsers.add_parser(
        'digest', aliases=['generate-digest'], prog=parser.prog + ' digest',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help='Generate loadable TA binary image digest for offline signing',
        epilog=textwrap.dedent('''\
            example offline signing command using OpenSSL for algorithm
            TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
              base64 -d <UUID>.dig | \\
              openssl pkeyutl -sign -inkey <KEYFILE>.pem \\
                  -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss \\
                  -pkeyopt rsa_pss_saltlen:digest \\
                  -pkeyopt rsa_mgf1_md:sha256 | \\
              base64 > <UUID>.sig

            example offline signing command using OpenSSL for algorithm
            TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
              base64 -d <UUID>.dig | \\
              openssl pkeyutl -sign -inkey <KEYFILE>.pem \\
                  -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | \\
              base64 > <UUID>.sig
            '''))
    arg_add_uuid(parser_digest)
    arg_add_ta_version(parser_digest)
    arg_add_in(parser_digest)
    arg_add_key(parser_digest)
    arg_add_enc_key(parser_digest)
    arg_add_enc_key_type(parser_digest)
    arg_add_algo(parser_digest)
    arg_add_dig(parser_digest)

    parser_stitch = subparsers.add_parser(
        'stitch', aliases=['stitch-ta'], prog=parser.prog + ' stich',
        help='Generate loadable signed and encrypted TA binary image file' +
        ' from TA raw image and its signature')
    arg_add_uuid(parser_stitch)
    arg_add_ta_version(parser_stitch)
    arg_add_in(parser_stitch)
    arg_add_key(parser_stitch)
    arg_add_out(parser_stitch)
    arg_add_enc_key(parser_stitch)
    arg_add_enc_key_type(parser_stitch)
    arg_add_algo(parser_stitch)
    arg_add_sig(parser_stitch)

    parser_verify = subparsers.add_parser(
        'verify', prog=parser.prog + ' verify',
        help='Verify signed TA binary')
    arg_add_uuid(parser_verify)
    arg_add_in(parser_verify)
    arg_add_key(parser_verify)

    argv = sys.argv[1:]
    if (len(argv) > 0 and argv[0][0] == '-' and
            argv[0] != '-h' and argv[0] != '--help'):
        # The default sub-command is 'sign-enc' so add it to the parser
        # if one is missing
        argv = ['sign-enc'] + argv

    parsed = parser.parse_args(argv)

    if parsed.command is None:
        parser.print_help()
        sys.exit(1)

    # Set a few defaults if defined for the current command
    assign_default_value(parsed, 'inf', get_inf_default)
    assign_default_value(parsed, 'outf', get_outf_default)
    assign_default_value(parsed, 'sigf', get_sigf_default)
    assign_default_value(parsed, 'digf', get_digf_default)

    return parsed


def main():
    from cryptography import exceptions
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import utils
    import base64
    import logging
    import os
    import struct

    logging.basicConfig()
    global logger
    logger = logging.getLogger(os.path.basename(__file__))

    args = get_args()

    if args.key.startswith('arn:'):
        from sign_helper_kms import _RSAPrivateKeyInKMS
        key = _RSAPrivateKeyInKMS(args.key)
    else:
        with open(args.key, 'rb') as f:
            data = f.read()

            try:
                key = serialization.load_pem_private_key(
                          data,
                          password=None,
                          backend=default_backend())
            except ValueError:
                key = serialization.load_pem_public_key(
                          data,
                          backend=default_backend())

    with open(args.inf, 'rb') as f:
        img = f.read()

    chosen_hash = hashes.SHA256()
    h = hashes.Hash(chosen_hash, default_backend())

    digest_len = chosen_hash.digest_size
    sig_len = math.ceil(key.key_size / 8)

    img_size = len(img)

    hdr_version = args.ta_version  # struct shdr_bootstrap_ta::ta_version

    magic = SHDR_MAGIC
    if args.enc_key:
        img_type = SHDR_ENCRYPTED_TA
    else:
        img_type = SHDR_BOOTSTRAP_TA

    shdr = struct.pack('<IIIIHH',
                       magic, img_type, img_size, algo[args.algo],
                       digest_len, sig_len)
    shdr_uuid = args.uuid.bytes
    shdr_version = struct.pack('<I', hdr_version)

    if args.enc_key:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher = AESGCM(bytes.fromhex(args.enc_key))
        # Use 12 bytes for nonce per recommendation
        nonce = os.urandom(12)
        out = cipher.encrypt(nonce, img, None)
        ciphertext = out[:-16]
        # Authentication Tag is always the last 16 bytes
        tag = out[-16:]

        enc_algo = 0x40000810      # TEE_ALG_AES_GCM
        flags = enc_key_type[args.enc_key_type]
        ehdr = struct.pack('<IIHH',
                           enc_algo, flags, len(nonce), len(tag))

    h.update(shdr)
    h.update(shdr_uuid)
    h.update(shdr_version)
    if args.enc_key:
        h.update(ehdr)
        h.update(nonce)
        h.update(tag)
    h.update(img)
    img_digest = h.finalize()

    def write_image_with_signature(sig):
        with open(args.outf, 'wb') as f:
            f.write(shdr)
            f.write(img_digest)
            f.write(sig)
            f.write(shdr_uuid)
            f.write(shdr_version)
            if args.enc_key:
                f.write(ehdr)
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
            else:
                f.write(img)

    def sign_encrypt_ta():
        if not isinstance(key, rsa.RSAPrivateKey):
            logger.error('Provided key cannot be used for signing, ' +
                         'please use offline-signing mode.')
            sys.exit(1)
        else:
            if args.algo == 'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256':
                sig = key.sign(
                    img_digest,
                    padding.PSS(
                        mgf=padding.MGF1(chosen_hash),
                        salt_length=digest_len
                    ),
                    utils.Prehashed(chosen_hash)
                )
            elif args.algo == 'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256':
                sig = key.sign(
                    img_digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(chosen_hash)
                )

            if len(sig) != sig_len:
                raise Exception(("Actual signature length is not equal to ",
                                 "the computed one: {} != {}").
                                format(len(sig), sig_len))
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
            try:
                if args.algo == 'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256':
                    key.verify(
                        sig,
                        img_digest,
                        padding.PSS(
                            mgf=padding.MGF1(chosen_hash),
                            salt_length=digest_len
                        ),
                        utils.Prehashed(chosen_hash)
                    )
                elif args.algo == 'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256':
                    key.verify(
                        sig,
                        img_digest,
                        padding.PKCS1v15(),
                        utils.Prehashed(chosen_hash)
                    )
            except exceptions.InvalidSignature:
                logger.error('Verification failed, ignoring given signature.')
                sys.exit(1)

            write_image_with_signature(sig)
            logger.info('Successfully applied signature.')

    def verify_ta():
        # Extract header
        [magic,
         img_type,
         img_size,
         algo_value,
         digest_len,
         sig_len] = struct.unpack('<IIIIHH', img[:SHDR_SIZE])

        # Extract digest and signature
        start, end = SHDR_SIZE, SHDR_SIZE + digest_len
        digest = img[start:end]

        start, end = end, SHDR_SIZE + digest_len + sig_len
        signature = img[start:end]

        # Extract UUID and TA version
        start, end = end, end + 16 + 4
        [uuid, ta_version] = struct.unpack('<16sI', img[start:end])

        if magic != SHDR_MAGIC:
            raise Exception("Unexpected magic: 0x{:08x}".format(magic))

        if img_type != SHDR_BOOTSTRAP_TA:
            raise Exception("Unsupported image type: {}".format(img_type))

        if algo_value not in algo.values():
            raise Exception('Unrecognized algorithm: 0x{:08x}'
                            .format(algo_value))

        # Verify signature against hash digest
        if algo_value == 0x70414930:
            key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(chosen_hash),
                    salt_length=digest_len
                ),
                utils.Prehashed(chosen_hash)
            )
        else:
            key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(chosen_hash)
            )

        h = hashes.Hash(chosen_hash, default_backend())

        # sizeof(struct shdr)
        h.update(img[:SHDR_SIZE])

        # sizeof(struct shdr_bootstrap_ta)
        h.update(img[start:end])

        # raw image
        start = end
        end += img_size
        h.update(img[start:end])

        if digest != h.finalize():
            raise Exception('Hash digest does not match')

        logger.info('Trusted application is correctly verified.')

    # dispatch command
    {
        'sign-enc': sign_encrypt_ta,
        'digest': generate_digest,
        'generate-digest': generate_digest,
        'stitch': stitch_ta,
        'stitch-ta': stitch_ta,
        'verify': verify_ta,
    }.get(args.command, 'sign_encrypt_ta')()


if __name__ == "__main__":
    main()
