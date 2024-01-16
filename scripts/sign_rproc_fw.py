#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2023, STMicroelectronics
#

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.enums import ENUM_P_TYPE_ARM
    from elftools.elf.enums import *
except ImportError:
    print("""
***
ERROR: "pyelftools" python module is not installed or version < 0.25.
***
""")
    raise

try:
    from Cryptodome.Hash import SHA256
    from Cryptodome.Signature import pkcs1_15
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import DSS
    from Cryptodome.PublicKey import ECC
except ImportError:
    print("""
            ***
            ERROR: "pycryptodomex" python module should be installed.
            ***
        """)
    raise

import os
import sys
import struct
import logging
import binascii

#  Generated file structure:
#
#                   -----+-------------+
#                  /     |    Magic    |  32-bit word, magic value equal to
#                 /      +-------------+  0x3543A468
#                /       +-------------+
#               /        |   version   |  32-bit word, version of the format
#              /         +-------------+
# +-----------+          +-------------+
# |   Header  |          |  TLV size   |  32-bit word, size of the TLV
# +-----------+          +-------------+  (aligned on 64-bit), in bytes.
#              \         +-------------+
#               \        |  sign size  |  32-bit word, size of the signature
#                \       +-------------+  (aligned on 64-bit), in bytes.
#                 \      +-------------+
#                  \     | images size |  32-bit word, size of the images to
#                   -----+-------------+  load (aligned on 64-bit), in bytes.
#
#                        +-------------+  Information used to authenticate the
#                        |     TLV     |  images and boot the remote processor,
#                        |             |  stored in Type-Length-Value format.
#                        +-------------+  'Type' and 'Length' are 32-bit words.
#
#                        +-------------+
#                        | Signature   |   Signature of the header and the TLV.
#                        +-------------+
#
#                        +-------------+
#                        |   Firmware  |
#                        |    image 1  |
#                        +-------------+
#                               ...
#                        +-------------+
#                        |   Firmware  |
#                        |    image n  |
#                        +-------------+

# Generic type definitions
TLV_TYPES = {
        'SIGNTYPE': 0x00000001,   # algorithm used for signature
        'HASHTYPE': 0x00000002,   # algorithm used for computing segment's hash
        'NUM_IMG':  0x00000003,   # number of images to load
        'IMGTYPE':  0x00000004,   # array of type of images to load
        'IMGSIZE':  0x00000005,   # array of the size of the images to load
        'HASHTABLE': 0x000000010,  # segment hash table for authentication
        'PKEYINFO': 0x0000000011,  # information to retrieve signature key
}

GENERIC_TLV_TYPE_RANGE = range(0x00000000, 0x00010000)
PLATFORM_TLV_TYPE_RANGE = range(0x00010000, 0x00020000)

HEADER_MAGIC = 0x3543A468

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

ENUM_HASH_TYPE = dict(
    SHA256=1,
)

ENUM_SIGNATURE_TYPE = dict(
    RSA=1,
    ECC=2,
)

ENUM_BINARY_TYPE = dict(
    ELF=1,
)


def dump_buffer(buf, step=16, name="", logger=logging.debug, indent=""):
    logger("%s%s:" % (indent, name))
    for i in range(0, len(buf), step):
        logger("%s    " % (indent) + " ".
               join(["%02X" % c for c in buf[i:i+step]]))
    logger("\n")


class TLV():
    def __init__(self):
        self.buf = bytearray()
        self.tlvs = {}

    def add(self, kind, payload):
        """
        Add a TLV record. Argument type is either the type scalar ID or a
        matching string defined in TLV_TYPES.
        """
        if isinstance(kind, int):
            buf = struct.pack('II', kind, len(payload))
        else:
            buf = struct.pack('II', TLV_TYPES[kind], len(payload))

        # Ensure that each TLV is 64-bit aligned
        align_64b = (len(payload) + len(buf)) % 8
        self.buf += buf
        self.buf += payload
        if align_64b:
            self.buf += bytearray(8 - align_64b)

    def add_plat_tlv(self, cust_tlv):
        # Get list of custom protected TLVs from the command-line
        for tlv in cust_tlv:
            type_id = int(tlv[0], 0)

            if type_id not in PLATFORM_TLV_TYPE_RANGE:
                raise Exception('TLV %s not in range' % hex(type_id))

            value = tlv[1]
            if value.startswith('0x'):
                int_val = int(value[2:], 16)
                self.tlvs[type_id] = int_val.to_bytes(4, 'little')
            else:
                self.tlvs[type_id] = value.encode('utf-8')

        if self.tlvs is not None:
            for type_id, value in self.tlvs.items():
                self.add(type_id, value)

    def get(self):
        """
        Get a byte-array that concatenates all the TLV added.
        """
        if len(self.buf) == 0:
            return bytes()
        return bytes(self.buf)


class RSA_Signature(object):

    def __init__(self, key):
        self._hasher = SHA256.new()
        self.signer = pkcs1_15.new(key)

    def hash_compute(self, segment):
        self._hasher.update(segment)

    def sign(self):
        return self.signer.sign(self._hasher)


class ECC_Signature(object):

    def __init__(self, key):
        self._hasher = SHA256.new()
        self.signer = DSS.new(key, 'fips-186-3')

    def hash_compute(self, segment):
        self._hasher.update(segment)

    def sign(self):
        return self.signer.sign(self._hasher)


Signature = {
        1: RSA_Signature,
        2: ECC_Signature,
}


class SegmentHashStruct:
    pass


class SegmentHash(object):
    '''
        Hash table based on Elf program segments
    '''
    def __init__(self, img):
        self._num_segments = img.num_segments()
        self._pack_fmt = '<%dL' % 8
        self.img = img
        self.hashProgTable = bytes()
        self._offset = 0

    def get_table(self):
        '''
            Create a segment hash table containing for each segment:
                - the segments header
                - a hash of the segment
        '''
        h = SHA256.new()
        seg = SegmentHashStruct()
        self.size = (h.digest_size + 32) * self._num_segments
        logging.debug("hash section size %d" % self.size)
        del h
        self.buf = bytearray(self.size)
        self._bufview_ = memoryview(self.buf)

        for i in range(self._num_segments):
            h = SHA256.new()
            segment = self.img.get_segment(i)
            seg.header = self.img.get_segment(i).header
            logging.debug("compute hash for segment offset %s" % seg.header)
            h.update(segment.data())
            seg.hash = h.digest()
            logging.debug("hash computed: %s" % seg.hash)
            del h
            struct.pack_into('<I', self._bufview_, self._offset,
                             ENUM_P_TYPE_ARM[seg.header.p_type])
            self._offset += 4
            struct.pack_into('<7I', self._bufview_, self._offset,
                             seg.header.p_offset, seg.header.p_vaddr,
                             seg.header.p_paddr, seg.header.p_filesz,
                             seg.header.p_memsz, seg.header.p_flags,
                             seg.header.p_align)
            self._offset += 28
            struct.pack_into('<32B', self._bufview_, self._offset, *seg.hash)
            self._offset += 32
        dump_buffer(self.buf, name='hash table', indent="\t")
        return self.buf


class ImageHeader(object):
    '''
        Image header
    '''

    magic = 'HELF'   # SHDR_MAGIC
    version = 1

    MAGIC_OFFSET = 0
    VERSION_OFFSET = 4
    SIGN_LEN_OFFSET = 8
    IMG_LEN_OFFSET = 12
    TLV_LEN_OFFSET = 16
    PTLV_LEN_OFFSET = 20

    def __init__(self):
        self.size = 56

        self.magic = HEADER_MAGIC
        self.version = 1
        self.tlv_length = 0
        self.sign_length = 0
        self.img_length = 0

        self.shdr = struct.pack('<IIIII',
                                self.magic, self.version,
                                self.tlv_length, self.sign_length,
                                self.img_length)

    def dump(self):
        logging.debug("\tMAGIC\t\t= %08X" % (self.magic))
        logging.debug("\tHEADER_VERSION\t= %08X" % (self.version))
        logging.debug("\tTLV_LENGTH\t= %08X" % (self.tlv_length))
        logging.debug("\tSIGN_LENGTH\t= %08X" % (self.sign_length))
        logging.debug("\tIMAGE_LENGTH\t= %08X" % (self.img_length))

    def get_packed(self):
        return struct.pack('<IIIII',
                           self.magic, self.version,
                           self.tlv_length, self.sign_length, self.img_length)


def get_args(logger):
    from argparse import ArgumentParser, RawDescriptionHelpFormatter
    import textwrap

    parser = ArgumentParser(
        description='Sign a remote processor firmware loadable by OP-TEE.',
        usage='\n   %(prog)s [ arguments ]\n\n'
        '   Generate signed loadable binary \n' +
        '   Takes arguments --in, --out --key\n' +
        '   %(prog)s --help  show available arguments\n\n')
    parser.add_argument('--in', required=True, dest='in_file',
                        help='Name of firmware input file ' +
                             '(can be used multiple times)', action='append')
    parser.add_argument('--out', required=True, dest='out_file',
                        help='Name of the signed firmware output file')
    parser.add_argument('--key', required=True,
                        help='Name of signing key file',
                        dest='key_file')
    parser.add_argument('--key_info', required=False,
                        help='Name file containing extra key information',
                        dest='key_info')
    parser.add_argument('--key_type', required=False,
                        help='Type of signing key: should be RSA or ECC',
                        default='RSA',
                        dest='key_type')
    parser.add_argument('--plat-tlv', required=False, nargs=2,
                        metavar=("ID", "value"), action='append',
                        help='Platform TLV that will be placed into image '
                             'plat_tlv area. Add "0x" prefix to interpret '
                             'the value as an integer, otherwise it will be '
                             'interpreted as a string. Option can be used '
                             'multiple times to add multiple TLVs.',
                        default=[], dest='plat_tlv')

    parsed = parser.parse_args()

    # Set defaults for optional arguments.

    if parsed.out_file is None:
        parsed.out_file = str(parsed.in_file)+'.sig'

    return parsed


def rsa_key(key_file):
    return RSA.importKey(open(key_file).read())


def ecc_key(key_file):
    return ECC.import_key(open(key_file).read())


key_type = {
        1: rsa_key,
        2: ecc_key,
}


def rsa_sig_size(key):
    return key.size_in_bytes()


def ecc_sig_size(key):
    # to be improve...
    # DSA size is N/4  so 64 for DSA (L,N) = (2048, 256)
    return 64


sig_size_type = {
        1: rsa_sig_size,
        2: ecc_sig_size,
}


def main():
    from Cryptodome.Signature import pss
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import RSA
    import base64
    import logging
    import struct

    logging.basicConfig()
    logger = logging.getLogger(os.path.basename(__file__))

    args = get_args(logger)

    # Initialise the header */
    s_header = ImageHeader()
    tlv = TLV()

    sign_type = ENUM_SIGNATURE_TYPE[args.key_type]
    get_key = key_type.get(sign_type, lambda: "Invalid sign type")

    key = get_key(args.key_file)

    if not key.has_private():
        logger.error('Provided key cannot be used for signing, ')
        sys.exit(1)

    tlv.add('SIGNTYPE', sign_type.to_bytes(1, 'little'))

    images_type = []
    hash_tlv = bytearray()
    images_size = []

    # Firmware image
    for inputf in args.in_file:
        logging.debug("image  %s" % inputf)
        input_file = open(inputf, 'rb')
        img = ELFFile(input_file)

        # Only ARM machine has been tested and well supported yet.
        # Indeed this script uses of ENUM_P_TYPE_ARM dic
        assert img.get_machine_arch() in ["ARM"]

        # Need to reopen the file to get the raw data
        with open(inputf, 'rb') as f:
            bin_img = f.read()
        size = len(bin_img)
        align_64b = size % 8
        if align_64b:
            size += 8 - align_64b

        images_size.extend(size.to_bytes(4, 'little'))
        s_header.img_length += size
        f.close()

        # Store image type information
        bin_type = ENUM_BINARY_TYPE['ELF']
        images_type += bin_type.to_bytes(1, 'little')

        # Compute the hash table and add it to TLV blob
        hash_table = SegmentHash(img)
        hash_tlv.extend(hash_table.get_table())

    # Add image information
    # The 'IMGTYPE' contains a byte array of the image type (ENUM_BINARY_TYPE).
    # The 'IMGSIZE' contains a byte array of the size (32-bit) of each image.
    tlv.add('NUM_IMG', len(args.in_file).to_bytes(1, 'little'))
    tlv.add('IMGTYPE', bytearray(images_type))
    tlv.add('IMGSIZE', bytearray(images_size))

    # Add hash type information in TLV blob
    # The 'HASHTYPE' TLV contains a byte associated to ENUM_HASH_TYPE.
    hash_type = ENUM_HASH_TYPE['SHA256']
    tlv.add('HASHTYPE', hash_type.to_bytes(1, 'little'))

    # Add hash table information in TLV blob
    # The HASHTABLE TLV contains a byte array containing all the ELF segment
    # with associated hash.
    tlv.add('HASHTABLE', hash_tlv)

    # Add optional key information to TLV
    if args.key_info:
        with open(args.key_info, 'rb') as f:
            key_info = f.read()
        tlv.add('PKEYINFO', key_info)

    # Compute custom TLV that will be passed to the platform PTA
    # Get list of custom protected TLVs from the command-line
    if args.plat_tlv:
        tlv.add_plat_tlv(args.plat_tlv)

    # Get the TLV area and compute its size (with 64 bit alignment)
    tlvs_buff = tlv.get()
    s_header.tlv_length = len(tlvs_buff)

    align_64b = 8 - (s_header.tlv_length % 8)
    if align_64b:
        s_header.tlv_length += 8 - align_64b
        tlvs_buff += bytearray(8 - align_64b)

    dump_buffer(tlvs_buff, name='TLVS', indent="\t")

    # Signature chunk
    sign_size = sig_size_type.get(ENUM_SIGNATURE_TYPE[args.key_type],
                                  lambda: "Invalid sign type")(key)
    s_header.sign_length = sign_size

    # Construct the Header
    header = s_header.get_packed()

    # Generate signature
    signer = Signature.get(ENUM_SIGNATURE_TYPE[args.key_type])(key)

    signer.hash_compute(header)
    signer.hash_compute(tlvs_buff)
    signature = signer.sign()
    if len(signature) != sign_size:
        raise Exception(("Actual signature length is not equal to ",
                         "the computed one: {} != {}".
                         format(len(signature), sign_size)))

    s_header.dump()

    with open(args.out_file, 'wb') as f:
        f.write(header)
        f.write(tlvs_buff)
        f.write(signature)
        align_64b = sign_size % 8
        if align_64b:
            f.write(bytearray(8 - align_64b))
        for inputf in args.in_file:
            with open(inputf, 'rb') as fin:
                bin_img = fin.read()
            f.write(bin_img)
            fin.close()
            align_64b = len(bin_img) % 8
            if align_64b:
                f.write(bytearray(8 - align_64b))


if __name__ == "__main__":
    main()
