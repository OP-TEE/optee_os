#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2021 Huawei Technologies Co., Ltd


def dump(msg, buf):
    import codecs

    print(msg, end='')
    print(codecs.encode(buf, 'hex').decode('utf-8'))


def main():
    import struct
    import sys

    img_type_name = {1: 'SHDR_BOOTSTRAP_TA', 2: 'SHDR_ENCRYPTED_TA'}
    algo_name = {0x70414930: 'RSASSA_PKCS1_PSS_MGF1_SHA256',
                 0x70004830: 'RSASSA_PKCS1_V1_5_SHA256'}

    with open(sys.argv[1], 'rb') as f:
        shdr = f.read(20)
        (magic, img_type, img_size, algo, digest_len,
            sig_len) = struct.unpack('<IIIIHH', shdr)
        print(f'Magic: 0x{magic:x} ', end='')
        if magic == 0x4f545348:  # SHDR_MAGIC
            print('(correct)')
        else:
            print('(**INCORRECT**)')
            return
        print(f'Image type: {img_type} ({img_type_name[img_type]})')
        print(f'Image size: {img_size} bytes')
        print(f'Signing algorithm: 0x{algo:x} ({algo_name[algo]})')
        print(f'Digest length: {digest_len} bytes')
        print(f'Signature length: {sig_len} bytes')
        digest = f.read(digest_len)
        dump('Digest: ', digest)


if __name__ == '__main__':
    main()
