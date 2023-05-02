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

TEE_ATTR_RSA_MODULUS = 0xD0000130
TEE_ATTR_RSA_PUBLIC_EXPONENT = 0xD0000230

SHDR_BOOTSTRAP_TA = 1
SHDR_ENCRYPTED_TA = 2
SHDR_SUBKEY = 3
SHDR_MAGIC = 0x4f545348
SHDR_SIZE = 20
SK_HDR_SIZE = 20
EHDR_SIZE = 12
UUID_SIZE = 16
# Use 12 bytes for nonce per recommendation
NONCE_SIZE = 12
TAG_SIZE = 16


def value_to_key(db, val):
    for k, v in db.items():
        if v == val:
            return k


def uuid_v5_sha512(namespace_bytes, name):
    from cryptography.hazmat.primitives import hashes
    from uuid import UUID

    h = hashes.Hash(hashes.SHA512())
    h.update(namespace_bytes + bytes(name, 'utf-8'))
    digest = h.finalize()
    return UUID(bytes=digest[:16], version=5)


def name_img_to_str(name_img):
    return name_img.decode().split('\x00', 1)[0]


def uuid_parse(s):
    from uuid import UUID
    return UUID(s)


def int_parse(str):
    return int(str, 0)


def get_args():
    import argparse
    import textwrap

    class OnlyOne(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            a = self.dest + '_assigned'
            if getattr(namespace, a, False):
                raise argparse.ArgumentError(self, 'Can only be given once')
            setattr(namespace, a, True)
            setattr(namespace, self.dest, values)

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

    def arg_add_subkey(parser):
        parser.add_argument(
            '--subkey', action=OnlyOne, help='Name of subkey input file')

    def arg_add_name(parser):
        parser.add_argument('--name',
                            help='Input name for subspace of a subkey')

    def arg_add_subkey_uuid_in(parser):
        parser.add_argument(
            '--in', required=True, dest='inf',
            help='Name of subkey input file')

    def arg_add_max_depth(parser):
        parser.add_argument(
            '--max-depth', required=False, type=int_parse, help='''
            Max depth of subkeys below this subkey''')

    def arg_add_name_size(parser):
        parser.add_argument(
            '--name-size', required=True, type=int_parse, help='''
            Size of (unsigned) input name for subspace of a subkey.
            Set to 0 to create an identity subkey (a subkey having
            the same UUID as the next subkey or TA)''')

    def arg_add_subkey_version(parser):
        parser.add_argument(
            '--subkey-version', required=False, type=int_parse, default=0,
            help='Subkey version used for rollback protection')

    def arg_add_subkey_in(parser):
        parser.add_argument(
            '--in', required=True, dest='inf', help='''
            Name of PEM file with the public key of the new subkey''')

    def arg_add_subkey_out(parser):
        parser.add_argument(
            '--out', required=True, dest='outf',
            help='Name of subkey output file')

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
    arg_add_subkey(parser_sign_enc)
    arg_add_name(parser_sign_enc)
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

    parser_display = subparsers.add_parser(
        'display', prog=parser.prog + ' display',
        help='Parses and displays a signed TA binary')
    parser_display.set_defaults(func=command_display)
    arg_add_in(parser_display)

    parser_subkey_uuid = subparsers.add_parser(
        'subkey-uuid', prog=parser.prog + ' subkey-uuid',
        help='calculate the UUID of next TA or subkey')
    parser_subkey_uuid.set_defaults(func=command_subkey_uuid)
    arg_add_subkey_uuid_in(parser_subkey_uuid)
    arg_add_name(parser_subkey_uuid)

    parser_sign_subkey = subparsers.add_parser(
        'sign-subkey', prog=parser.prog + ' sign-subkey',
        help='Sign a subkey')
    parser_sign_subkey.set_defaults(func=command_sign_subkey)
    arg_add_name(parser_sign_subkey)
    arg_add_subkey_in(parser_sign_subkey)
    arg_add_uuid(parser_sign_subkey)
    arg_add_key(parser_sign_subkey)
    arg_add_subkey_out(parser_sign_subkey)
    arg_add_max_depth(parser_sign_subkey)
    arg_add_name_size(parser_sign_subkey)
    arg_add_subkey(parser_sign_subkey)
    arg_add_subkey_version(parser_sign_subkey)
    arg_add_algo(parser_sign_subkey)

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


def load_asymmetric_key_img(data):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key)

    try:
        return load_pem_private_key(data, password=None,
                                    backend=default_backend())
    except ValueError:
        return load_pem_public_key(data, backend=default_backend())


def load_asymmetric_key(arg_key):
    if arg_key.startswith('arn:'):
        from sign_helper_kms import _RSAPrivateKeyInKMS
        return _RSAPrivateKeyInKMS(arg_key)
    else:
        with open(arg_key, 'rb') as f:
            return load_asymmetric_key_img(f.read())


class BinaryImage:
    def __init__(self, arg_inf, arg_key):
        from cryptography.hazmat.primitives import hashes

        # Exactly what inf is holding isn't determined a this stage
        if isinstance(arg_inf, str):
            with open(arg_inf, 'rb') as f:
                self.inf = f.read()
        else:
            self.inf = arg_inf

        if arg_key is None:
            self.key = None
        else:
            if isinstance(arg_key, str):
                self.key = load_asymmetric_key(arg_key)
            else:
                self.key = arg_key
            self.sig_size = math.ceil(self.key.key_size / 8)

        self.chosen_hash = hashes.SHA256()
        self.hash_size = self.chosen_hash.digest_size

    def __pack_img(self, img_type, sign_algo):
        import struct

        self.sig_algo = sign_algo
        self.img_type = img_type
        self.shdr = struct.pack('<IIIIHH', SHDR_MAGIC, img_type, len(self.img),
                                sig_tee_alg[sign_algo], self.hash_size,
                                self.sig_size)

    def __calc_digest(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes

        h = hashes.Hash(self.chosen_hash, default_backend())
        h.update(self.shdr)
        if hasattr(self, 'ta_uuid'):
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

    def set_subkey(self, sign_algo, name, uuid, subkey_version, max_depth,
                   name_size):
        from cryptography.hazmat.primitives.asymmetric import rsa
        import struct

        self.subkey_name = name

        subkey_key = load_asymmetric_key_img(self.inf)
        if isinstance(subkey_key, rsa.RSAPrivateKey):
            subkey_pkey = subkey_key.public_key()
        else:
            subkey_pkey = subkey_key

        if max_depth is None:
            if hasattr(self, 'previous_max_depth'):
                if self.previous_max_depth <= 0:
                    logger.error('Max depth of previous subkey is {}, '
                                 .format(self.previous_max_depth) +
                                 'cannot use a smaller value')
                    sys.exit(1)

                max_depth = self.previous_max_depth - 1
            else:
                max_depth = 0
        else:
            if (hasattr(self, 'previous_max_depth') and
                    max_depth >= getattr(self, 'previous_max_depth')):
                logger.error('Max depth of previous subkey is {} '
                             .format(self.previous_max_depth) +
                             'and the next value must be smaller')
                sys.exit(1)

        def int_to_bytes(x: int) -> bytes:
            return x.to_bytes((x.bit_length() + 8) // 8, 'big')

        n_bytes = int_to_bytes(subkey_pkey.public_numbers().n)
        e_bytes = int_to_bytes(subkey_pkey.public_numbers().e)
        attrs_end_offs = 16 + 5 * 4 + 2 * 3 * 4
        shdr_subkey = struct.pack('<IIIIIIIIIII',
                                  name_size, subkey_version,
                                  max_depth, sig_tee_alg[sign_algo], 2,
                                  TEE_ATTR_RSA_MODULUS,
                                  attrs_end_offs, len(n_bytes),
                                  TEE_ATTR_RSA_PUBLIC_EXPONENT,
                                  attrs_end_offs + len(n_bytes),
                                  len(e_bytes))
        self.img = uuid.bytes + shdr_subkey + n_bytes + e_bytes
        self.__pack_img(SHDR_SUBKEY, sign_algo)
        self.img_digest = self.__calc_digest()

    def parse(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        import struct

        offs = 0
        self.shdr = self.inf[offs:offs + SHDR_SIZE]
        [magic, img_type, img_size, algo_value, hash_size,
         sig_size] = struct.unpack('<IIIIHH', self.shdr)
        offs += SHDR_SIZE

        if magic != SHDR_MAGIC:
            raise Exception("Unexpected magic: 0x{:08x}".format(magic))

        if algo_value not in sig_tee_alg.values():
            raise Exception('Unrecognized algorithm: 0x{:08x}'
                            .format(algo_value))
        self.sig_algo = value_to_key(sig_tee_alg, algo_value)

        if hash_size != self.hash_size:
            raise Exception("Unexpected digest len: {}".format(hash_size))

        self.img_digest = self.inf[offs:offs + hash_size]
        offs += hash_size
        self.sig = self.inf[offs:offs + sig_size]
        offs += sig_size

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
                self.img = self.ciphertext
            else:
                self.img = self.inf[offs:]
                if len(self.img) != img_size:
                    raise Exception("Unexpected img size: got {}, expected {}"
                                    .format(len(self.img), img_size))
        elif img_type == SHDR_SUBKEY:
            subkey_offs = offs
            self.uuid = self.inf[offs:offs + UUID_SIZE]
            offs += UUID_SIZE
            self.subkey_hdr = self.inf[offs:offs + SK_HDR_SIZE]
            [self.name_size, self.subkey_version, self.max_depth, self.algo,
             self.attr_count] = struct.unpack('<IIIII', self.subkey_hdr)
            offs += len(self.subkey_hdr)
            self.attr = self.inf[offs:offs + img_size -
                                 UUID_SIZE - len(self.subkey_hdr)]
            offs += len(self.attr)
            self.name_img = self.inf[offs:offs + self.name_size]
            offs += self.name_size
            self.next_inf = self.inf[offs:]

            def find_attr(attr):
                if self.attr_count <= 0:
                    return None
                for n in range(self.attr_count):
                    o = subkey_offs + UUID_SIZE + SK_HDR_SIZE + n * 12
                    [attr_value, attr_offs,
                     attr_len] = struct.unpack('<III', self.inf[o: o + 12])
                    if attr_value == attr:
                        o = subkey_offs + attr_offs
                        return self.inf[o:o + attr_len]
                return None

            n_bytes = find_attr(TEE_ATTR_RSA_MODULUS)
            e_bytes = find_attr(TEE_ATTR_RSA_PUBLIC_EXPONENT)
            e = int.from_bytes(e_bytes, 'big')
            n = int.from_bytes(n_bytes, 'big')
            self.subkey_key = rsa.RSAPublicNumbers(e, n).public_key()

            self.img = self.inf[subkey_offs:offs - self.name_size]
            if len(self.img) != img_size:
                raise Exception("Unexpected img size: got {}, expected {}"
                                .format(len(self.img), img_size))
        else:
            raise Exception("Unsupported image type: {}".format(img_type))

    def display(self):
        import binascii
        import struct
        import uuid

        def display_ta():
            nonlocal offs
            ta_uuid = self.inf[offs:offs + UUID_SIZE]
            print(' struct shdr_bootstrap_ta')
            print('  uuid:       {}'.format(uuid.UUID(bytes=ta_uuid)))
            offs += UUID_SIZE
            [ta_version] = struct.unpack('<I', self.inf[offs:offs + 4])
            print('  ta_version: {}'.format(ta_version))

            offs += 4
            if img_type == SHDR_ENCRYPTED_TA:
                ehdr = self.inf[offs: offs + EHDR_SIZE]
                offs += EHDR_SIZE
                [enc_algo, flags, nonce_len,
                 tag_len] = struct.unpack('<IIHH', ehdr)

                print(' struct shdr_encrypted_ta')
                enc_algo_name = 'Unkown'
                if enc_algo in enc_tee_alg.values():
                    enc_algo_name = value_to_key(enc_tee_alg, enc_algo)
                print('  enc_algo:   0x{:08x} ({})'
                      .format(enc_algo, enc_algo_name))

                if enc_algo not in enc_tee_alg.values():
                    raise Exception('Unrecognized encrypt algorithm: 0x{:08x}'
                                    .format(enc_value))

                flags_name = 'Unkown'
                if flags in enc_key_type.values():
                    flags_name = value_to_key(enc_key_type, flags)
                print('  flags:      0x{:x} ({})'.format(flags, flags_name))

                print('  iv_size:    {} (bytes)'.format(nonce_len))
                if nonce_len != NONCE_SIZE:
                    raise Exception("Unexpected nonce len: {}"
                                    .format(nonce_len))
                nonce = self.inf[offs:offs + nonce_len]
                print('  iv:         {}'
                      .format(binascii.hexlify(nonce).decode('ascii')))
                offs += nonce_len

                print('  tag_size:   {} (bytes)'.format(tag_len))
                if tag_len != TAG_SIZE:
                    raise Exception("Unexpected tag len: {}".format(tag_len))
                tag = self.inf[-tag_len:]
                print('  tag:        {}'
                      .format(binascii.hexlify(tag).decode('ascii')))
                ciphertext = self.inf[offs:-tag_len]
                print(' TA offset:  {} (0x{:x}) bytes'.format(offs, offs))
                print(' TA size:    {} (0x{:x}) bytes'
                      .format(len(ciphertext), len(ciphertext)))
                if len(ciphertext) != img_size:
                    raise Exception("Unexpected ciphertext size: ",
                                    "got {}, expected {}"
                                    .format(len(ciphertext), img_size))
                offs += tag_len
            else:
                img = self.inf[offs:]
                print(' TA offset:  {} (0x{:x}) bytes'.format(offs, offs))
                print(' TA size:    {} (0x{:x}) bytes'
                      .format(len(img), len(img)))
                if len(img) != img_size:
                    raise Exception("Unexpected img size: got {}, expected {}"
                                    .format(len(img), img_size))
            offs += img_size

        offs = 0
        while offs < len(self.inf):
            if offs > 0:
                # name_size is the previous subkey header
                name_img = self.inf[offs:offs + name_size]
                print('  next name:  "{}"'.format(name_img_to_str(name_img)))
                offs += name_size
                print('Next header at offset: {} (0x{:x})'
                      .format(offs, offs))

            shdr = self.inf[offs:offs + SHDR_SIZE]
            [magic, img_type, img_size, algo_value, hash_size,
             sig_size] = struct.unpack('<IIIIHH', shdr)
            offs += SHDR_SIZE

            if magic != SHDR_MAGIC:
                Exception("Unexpected magic: 0x{:08x}".format(magic))

            img_type_name = 'Unknown'
            if img_type == SHDR_BOOTSTRAP_TA:
                print('Bootstrap TA')
                img_type_name = 'SHDR_BOOTSTRAP_TA'
            if img_type == SHDR_ENCRYPTED_TA:
                print('Encrypted TA')
                img_type_name = 'SHDR_ENCRYPTED_TA'
            if img_type == SHDR_SUBKEY:
                print('Subkey')
                img_type_name = 'SHDR_SUBKEY'

            algo_name = 'Unknown'
            if algo_value in sig_tee_alg.values():
                algo_name = value_to_key(sig_tee_alg, algo_value)

            print(' struct shdr')
            print('  magic:      0x{:08x}'.format(magic))
            print('  img_type:   {} ({})'.format(img_type, img_type_name))
            print('  img_size:   {} bytes'.format(img_size))
            print('  algo:       0x{:08x} ({})'.format(algo_value, algo_name))
            print('  hash_size:  {} bytes'.format(hash_size))
            print('  sig_size:   {} bytes'.format(sig_size))

            if algo_value not in sig_tee_alg.values():
                raise Exception('Unrecognized algorithm: 0x{:08x}'
                                .format(algo_value))

            if hash_size != self.hash_size:
                raise Exception("Unexpected digest len: {}".format(hash_size))

            img_digest = self.inf[offs:offs + hash_size]
            print('  hash:       {}'
                  .format(binascii.hexlify(img_digest).decode('ascii')))
            offs += hash_size
            sig = self.inf[offs:offs + sig_size]
            offs += sig_size

            if img_type == SHDR_BOOTSTRAP_TA or img_type == SHDR_ENCRYPTED_TA:
                display_ta()
            elif img_type == SHDR_SUBKEY:
                img_uuid = self.inf[offs:offs + UUID_SIZE]
                img_subkey = self.inf[offs + UUID_SIZE:
                                      offs + UUID_SIZE + SK_HDR_SIZE]
                [name_size, subkey_version, max_depth, algo,
                 attr_count] = struct.unpack('<IIIII', img_subkey)
                if algo not in sig_tee_alg.values():
                    raise Exception('Unrecognized algorithm: 0x{:08x}'
                                    .format(algo))
                algo_name = value_to_key(sig_tee_alg, algo)
                print(' struct shdr_subkey')
                print('  uuid:       {}'.format(uuid.UUID(bytes=img_uuid)))
                print('  name_size:  {}'.format(name_size))
                print('  subkey_version: {}'.format(subkey_version))
                print('  max_depth:  {}'.format(max_depth))
                print('  algo:       0x{:08x} ({})'.format(algo, algo_name))
                print('  attr_count: {}'.format(attr_count))
                offs += img_size
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
                              salt_length=self.hash_size)
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

            if len(self.sig) != self.sig_size:
                raise Exception(("Actual signature length is not equal to ",
                                 "the computed one: {} != {}").
                                format(len(self.sig), self.sig_size))

    def add_signature(self, sigf):
        import base64

        with open(sigf, 'r') as f:
            self.sig = base64.b64decode(f.read())

        if len(self.sig) != self.sig_size:
            raise Exception(("Actual signature length is not equal to ",
                             "the expected one: {} != {}").
                            format(len(self.sig), self.sig_size))

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

    def add_subkey(self, subkey_file, name):
        sk_image = BinaryImage(subkey_file, None)
        self.subkey_img = sk_image.inf
        sk_image.parse()
        if not hasattr(sk_image, 'next_inf'):
            logger.error('Invalid subkey file')
            sys.exit(1)
        while len(sk_image.next_inf) > 0:
            sk_image = BinaryImage(sk_image.next_inf, None)
            sk_image.parse()

        if name is None:
            name = ''
        self.previous_max_depth = sk_image.max_depth
        self.name_img = str.encode(name).ljust(sk_image.name_size, b'\0')

    def write(self, outf):
        with open(outf, 'wb') as f:
            if hasattr(self, 'subkey_img'):
                f.write(self.subkey_img)
                f.write(self.name_img)
            f.write(self.shdr)
            f.write(self.img_digest)
            f.write(self.sig)
            if hasattr(self, 'ta_uuid'):
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
    if args.subkey:
        ta_image.add_subkey(args.subkey, args.name)
    ta_image.sign()
    ta_image.write(args.outf)
    logger.info('Successfully signed application.')


def command_sign_subkey(args):
    image = BinaryImage(args.inf, args.key)
    if args.subkey:
        image.add_subkey(args.subkey, args.name)
    image.set_subkey(args.algo, args.name, args.uuid, args.subkey_version,
                     args.max_depth, args.name_size)
    image.sign()
    image.write(args.outf)
    logger.info('Successfully signed subkey.')


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
    import uuid

    image = BinaryImage(args.inf, args.key)
    next_uuid = None
    max_depth = -1
    while True:
        image.parse()
        if hasattr(image, 'subkey_hdr'):  # Subkey
            print('Subkey UUID: {}'.format(uuid.UUID(bytes=image.uuid)))
            image.verify_signature()
            image.verify_digest()
            if next_uuid:
                if uuid.UUID(bytes=image.uuid) != next_uuid:
                    raise Exception('UUID {} does not match {}'
                                    .format(uuid.UUID(bytes=image.uuid),
                                            next_uuid))
            if max_depth >= 0:
                if image.max_depth < 0 or image.max_depth >= max_depth:
                    raise Exception('Invalid max_depth {} not less than {}'
                                    .format(image.max_depth, max_depth))
            max_depth = image.max_depth
            if len(image.next_inf) == 0:
                logger.info('Subkey is correctly verified.')
                return
            if image.name_size > 0:
                next_uuid = uuid_v5_sha512(image.uuid,
                                           name_img_to_str(image.name_img))
            else:
                next_uuid = image.uuid
            image = BinaryImage(image.next_inf, image.subkey_key)
        else:  # TA
            print('TA UUID: {}'.format(uuid.UUID(bytes=image.ta_uuid)))
            if next_uuid:
                if uuid.UUID(bytes=image.ta_uuid) != next_uuid:
                    raise Exception('UUID {} does not match {}'
                                    .format(uuid.UUID(bytes=image.ta_uuid),
                                            next_uuid))
            if hasattr(image, 'ciphertext'):
                if args.enc_key is None:
                    logger.error('--enc_key needed to decrypt TA')
                    sys.exit(1)
                image.decrypt_ta(args.enc_key)
            image.verify_signature()
            image.verify_digest()
            image.verify_uuid(args.uuid)
            logger.info('Trusted application is correctly verified.')
            return


def command_display(args):
    ta_image = BinaryImage(args.inf, None)
    ta_image.display()


def command_subkey_uuid(args):
    import uuid

    sk_image = BinaryImage(args.inf, None)
    sk_image.parse()
    if not hasattr(sk_image, 'next_inf'):
        logger.error('Invalid subkey file')
        sys.exit(1)
    print('Subkey UUID: {}'.format(uuid.UUID(bytes=sk_image.uuid)))
    while len(sk_image.next_inf) > 0:
        sk_image = BinaryImage(sk_image.next_inf, None)
        sk_image.parse()
        print('Subkey UUID: {}'.format(uuid.UUID(bytes=sk_image.uuid)))
    if args.name:
        if len(args.name) > sk_image.name_size:
            logger.error('Length of name ({}) '.format(len(args.name)) +
                         'is larger than max name size ({})'
                         .format(sk_image.name_size))
            sys.exit(1)
        print('Next subkey UUID: {}'
              .format(uuid_v5_sha512(sk_image.uuid, args.name)))
    else:
        print('Next subkey UUID unchanged: {}'
              .format(uuid.UUID(bytes=sk_image.uuid)))


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
