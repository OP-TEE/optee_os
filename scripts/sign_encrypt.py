#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2015, 2017, 2019, Linaro Limited
#

import sys
import math


sig_tee_alg = {'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256': 0x70414930,
               'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256': 0x70004830}

enc_tee_alg = {'TEE_ALG_AES_GCM': 0x40000810}

enc_key_type = {'SHDR_ENC_KEY_DEV_SPECIFIC': 0x0,
                'SHDR_ENC_KEY_CLASS_WIDE': 0x1}

SHDR_BOOTSTRAP_TA = 1
SHDR_ENCRYPTED_TA = 2
SHDR_MAGIC = 0x4f545348
SHDR_SIZE = 20
EHDR_SIZE = 12
UUID_SIZE = 16
# Use 12 bytes for nonce per recommendation
NONCE_SIZE = 12
TAG_SIZE = 16


def value_to_key(db, val):
    for k, v in db.items():
        if v == val:
            return k


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
            '--algo', required=False, choices=list(sig_tee_alg.keys()),
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
    parser_sign_enc.set_defaults(func=command_sign_enc)
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
    parser_digest.set_defaults(func=command_digest)
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
    parser_stitch.set_defaults(func=command_stitch)
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
    parser_verify.set_defaults(func=command_verify)
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


def load_asymmetric_key(arg_key):
    if arg_key.startswith('arn:'):
        from sign_helper_kms import _RSAPrivateKeyInKMS
        key = _RSAPrivateKeyInKMS(arg_key)
    else:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_pem_public_key)

        with open(arg_key, 'rb') as f:
            data = f.read()

            try:
                key = load_pem_private_key(data, password=None,
                                           backend=default_backend())
            except ValueError:
                key = load_pem_public_key(data, backend=default_backend())

    return key


class BinaryImage:
    def __init__(self, arg_inf, arg_key):
        from cryptography.hazmat.primitives import hashes

        # Exactly what inf is holding isn't determined a this stage
        with open(arg_inf, 'rb') as f:
            self.inf = f.read()

        self.key = load_asymmetric_key(arg_key)

        self.chosen_hash = hashes.SHA256()
        self.digest_len = self.chosen_hash.digest_size
        self.sig_len = math.ceil(self.key.key_size / 8)

    def __pack_img(self, img_type, sign_algo):
        import struct

        self.sig_algo = sign_algo
        self.img_type = img_type
        self.shdr = struct.pack('<IIIIHH', SHDR_MAGIC, img_type, len(self.img),
                                sig_tee_alg[sign_algo], self.digest_len,
                                self.sig_len)

    def __calc_digest(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes

        h = hashes.Hash(self.chosen_hash, default_backend())
        h.update(self.shdr)
        h.update(self.ta_uuid)
        h.update(self.ta_version)
        if hasattr(self, 'ehdr'):
            h.update(self.ehdr)
            h.update(self.nonce)
            h.update(self.tag)
        h.update(self.img)
        return h.finalize()

    def encrypt_ta(self, enc_key, key_type, sig_algo, uuid, ta_version):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import struct
        import os

        self.img = self.inf

        cipher = AESGCM(bytes.fromhex(enc_key))
        self.nonce = os.urandom(NONCE_SIZE)
        out = cipher.encrypt(self.nonce, self.img, None)
        self.ciphertext = out[:-TAG_SIZE]
        # Authentication Tag is always the last bytes
        self.tag = out[-TAG_SIZE:]

        enc_algo = enc_tee_alg['TEE_ALG_AES_GCM']
        flags = enc_key_type[key_type]
        self.ehdr = struct.pack('<IIHH', enc_algo, flags, len(self.nonce),
                                len(self.tag))

        self.__pack_img(SHDR_ENCRYPTED_TA, sig_algo)
        self.ta_uuid = uuid.bytes
        self.ta_version = struct.pack('<I', ta_version)
        self.img_digest = self.__calc_digest()

    def set_bootstrap_ta(self, sig_algo, uuid, ta_version):
        import struct

        self.img = self.inf
        self.__pack_img(SHDR_BOOTSTRAP_TA, sig_algo)
        self.ta_uuid = uuid.bytes
        self.ta_version = struct.pack('<I', ta_version)
        self.img_digest = self.__calc_digest()

    def parse(self):
        import struct

        offs = 0
        self.shdr = self.inf[offs:offs + SHDR_SIZE]
        [magic, img_type, img_size, algo_value, digest_len,
         sig_len] = struct.unpack('<IIIIHH', self.shdr)
        offs += SHDR_SIZE

        if magic != SHDR_MAGIC:
            raise Exception("Unexpected magic: 0x{:08x}".format(magic))

        if algo_value not in sig_tee_alg.values():
            raise Exception('Unrecognized algorithm: 0x{:08x}'
                            .format(algo_value))
        self.sig_algo = value_to_key(sig_tee_alg, algo_value)

        if digest_len != self.digest_len:
            raise Exception("Unexpected digest len: {}".format(digest_len))

        self.img_digest = self.inf[offs:offs + digest_len]
        offs += digest_len
        self.sig = self.inf[offs:offs + sig_len]
        offs += sig_len

        if img_type == SHDR_BOOTSTRAP_TA or img_type == SHDR_ENCRYPTED_TA:
            self.ta_uuid = self.inf[offs:offs + UUID_SIZE]
            offs += UUID_SIZE
            self.ta_version = self.inf[offs:offs + 4]
            offs += 4
            if img_type == SHDR_ENCRYPTED_TA:
                self.ehdr = self.inf[offs: offs + EHDR_SIZE]
                offs += EHDR_SIZE
                [enc_algo, flags, nonce_len,
                 tag_len] = struct.unpack('<IIHH', self.ehdr)
                if enc_value not in enc_tee_alg.values():
                    raise Exception('Unrecognized encrypt algorithm: 0x{:08x}'
                                    .format(enc_value))
                if nonce_len != 12:
                    raise Exception("Unexpected nonce len: {}"
                                    .format(nonce_len))
                self.nonce = self.inf[offs:offs + nonce_len]
                offs += nonce_len

                if tag_len != 16:
                    raise Exception("Unexpected tag len: {}".format(tag_len))
                self.tag = self.inf[-tag_len:]
                self.ciphertext = self.inf[offs:-tag_len]
                if len(self.ciphertext) != img_size:
                    raise Exception("Unexpected ciphertext size: ",
                                    "got {}, expected {}"
                                    .format(len(self.ciphertext), img_size))
            else:
                self.img = self.inf[offs:]
                if len(self.img) != img_size:
                    raise Exception("Unexpected img size: got {}, expected {}"
                                    .format(len(self.img), img_size))
        else:
            raise Exception("Unsupported image type: {}".format(img_type))

    def decrypt_ta(enc_key):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        cipher = AESGCM(bytes.fromhex(enc_key))
        self.img = cipher.decrypt(self.nonce, self.ciphertext, None)

    def __get_padding(self):
        from cryptography.hazmat.primitives.asymmetric import padding

        if self.sig_algo == 'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256':
            pad = padding.PSS(mgf=padding.MGF1(self.chosen_hash),
                              salt_length=self.digest_len)
        elif self.sig_algo == 'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256':
            pad = padding.PKCS1v15()

        return pad

    def sign(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        from cryptography.hazmat.primitives.asymmetric import rsa

        if not isinstance(self.key, rsa.RSAPrivateKey):
            logger.error('Provided key cannot be used for signing, ' +
                         'please use offline-signing mode.')
            sys.exit(1)
        else:
            self.sig = self.key.sign(self.img_digest, self.__get_padding(),
                                     utils.Prehashed(self.chosen_hash))

            if len(self.sig) != self.sig_len:
                raise Exception(("Actual signature length is not equal to ",
                                 "the computed one: {} != {}").
                                format(len(self.sig), self.sig_len))

    def add_signature(self, sigf):
        import base64

        with open(sigf, 'r') as f:
            self.sig = base64.b64decode(f.read())

        if len(self.sig) != self.sig_len:
            raise Exception(("Actual signature length is not equal to ",
                             "the expected one: {} != {}").
                            format(len(self.sig), self.sig_len))

    def verify_signature(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import exceptions

        if isinstance(self.key, rsa.RSAPrivateKey):
            pkey = self.key.public_key()
        else:
            pkey = self.key

        try:
            pkey.verify(self.sig, self.img_digest, self.__get_padding(),
                        utils.Prehashed(self.chosen_hash))
        except exceptions.InvalidSignature:
            logger.error('Verification failed, ignoring given signature.')
            sys.exit(1)

    def verify_digest(self):
        if self.img_digest != self.__calc_digest():
            raise Exception('Hash digest does not match')

    def verify_uuid(self, uuid):
        if self.ta_uuid != uuid.bytes:
            raise Exception('UUID does not match')

    def write(self, outf):
        with open(outf, 'wb') as f:
            f.write(self.shdr)
            f.write(self.img_digest)
            f.write(self.sig)
            f.write(self.ta_uuid)
            f.write(self.ta_version)
            if hasattr(self, 'ehdr'):
                f.write(self.ehdr)
                f.write(self.nonce)
                f.write(self.tag)
                f.write(self.ciphertext)
            else:
                f.write(self.img)


def load_ta_image(args):
    ta_image = BinaryImage(args.inf, args.key)

    if args.enc_key:
        ta_image.encrypt_ta(args.enc_key, args.enc_key_type,
                            args.algo, args.uuid, args.ta_version)
    else:
        ta_image.set_bootstrap_ta(args.algo, args.uuid, args.ta_version)

    return ta_image


def command_sign_enc(args):
    ta_image = load_ta_image(args)
    ta_image.sign()
    ta_image.write(args.outf)
    logger.info('Successfully signed application.')


def command_digest(args):
    import base64

    ta_image = load_ta_image(args)
    with open(args.digf, 'wb+') as digfile:
        digfile.write(base64.b64encode(ta_image.img_digest))


def command_stitch(args):
    ta_image = load_ta_image(args)
    ta_image.add_signature(args.sigf)
    ta_image.verify_signature()
    ta_image.write(args.outf)
    logger.info('Successfully applied signature.')


def command_verify(args):
    ta_image = BinaryImage(args.inf, args.key)
    ta_image.parse()
    if hasattr(ta_image, 'ciphertext'):
        if args.enc_key is None:
            logger.error('--enc_key needed to decrypt TA')
            sys.exit(1)
        ta_image.decrypt_ta(args.enc_key)
    ta_image.verify_signature()
    ta_image.verify_digest()
    ta_image.verify_uuid(args.uuid)
    logger.info('Trusted application is correctly verified.')


def main():
    import logging
    import os

    global logger
    logging.basicConfig()
    logger = logging.getLogger(os.path.basename(__file__))

    args = get_args()
    args.func(args)


if __name__ == "__main__":
    main()
