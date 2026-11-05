#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2015, Linaro Limited

# Main algorithms as defined by the TEE Internal Core API specification
TEE_MAIN_ALGO_RSA = 0x30
TEE_MAIN_ALGO_ECDSA = 0x41

TEE_ECC_CURVE_NIST_P256 = 0x00000003


def get_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--prefix', required=True,
        help='Name of the TA public key or prefix for RSA key variables')
    parser.add_argument(
        '--out', required=True,
        help='Name of c file for the public key')
    parser.add_argument('--key', required=True, help='Name of key file')
    parser.add_argument('--ta', action='store_true',
                        help='Emit a struct ta_pub_key for TA verification')

    return parser.parse_args()


def emit_bytes(f, data, indent=''):
    for offset in range(0, len(data), 8):
        f.write(indent + ', '.join('0x{:02x}'.format(x)
                                   for x in data[offset:offset + 8]) + ',\n')


def main():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    args = get_args()

    with open(args.key, 'rb') as f:
        data = f.read()

        try:
            key = serialization.load_pem_private_key(data, password=None,
                                                     backend=default_backend())
            key = key.public_key()
        except ValueError:
            key = serialization.load_pem_public_key(data,
                                                    backend=default_backend())

    if isinstance(key, rsa.RSAPublicKey):
        main_algo = TEE_MAIN_ALGO_RSA

        # Refuse public exponent with more than 32 bits. Otherwise the C
        # compiler may simply truncate the value and proceed.
        # This will lead to TAs seemingly having invalid signatures with a
        # possible security issue for any e = k*2^32 + 1 (for any integer k).
        if key.public_numbers().e > 0xffffffff:
            raise ValueError(
                'Unsupported large public exponent detected. ' +
                'OP-TEE handles only public exponents up to 2^32 - 1.')

        exponent = key.public_numbers().e
        key_data = key.public_numbers().n.to_bytes(key.key_size >> 3, 'big')
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if not args.ta:
            raise ValueError('ECC keys require --ta')

        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(
                'Unsupported curve {}, '.format(key.curve.name) +
                'only NIST P-256 (secp256r1) is supported.')

        main_algo = TEE_MAIN_ALGO_ECDSA
        curve = TEE_ECC_CURVE_NIST_P256
        ecc_size = (key.curve.key_size + 7) // 8
        key_data = (key.public_numbers().x.to_bytes(ecc_size, 'big') +
                    key.public_numbers().y.to_bytes(ecc_size, 'big'))
    else:
        raise ValueError('Unsupported key type {}'.format(type(key).__name__))

    with open(args.out, 'w') as f:
        if args.ta:
            f.write("#include <ta_pub_key.h>\n\n")
            f.write("const struct ta_pub_key " + args.prefix + " = {\n")
            f.write("\t.main_algo = 0x{:02x},\n".format(main_algo))
            if main_algo == TEE_MAIN_ALGO_RSA:
                f.write("\t.rsa = {\n")
                f.write("\t\t.exponent = {},\n".format(exponent))
                f.write("\t\t.modulus_size = {},\n".format(len(key_data)))
            else:
                f.write("\t.ecc = {\n")
                f.write("\t\t.curve = {},\n".format(curve))
                f.write("\t\t.xy_size = {},\n".format(ecc_size))
            f.write("\t},\n\t.bin = {\n")
            emit_bytes(f, key_data, '\t\t')
            f.write("\t},\n};\n")
        else:
            f.write("#include <stdint.h>\n")
            f.write("#include <stddef.h>\n\n")
            f.write("const uint32_t " + args.prefix + "_exponent = " +
                    str(exponent) + ";\n\n")
            f.write("const uint8_t " + args.prefix + "_modulus[] = {\n")
            emit_bytes(f, key_data)
            f.write("};\n")
            f.write("const size_t " + args.prefix + "_modulus_size = " +
                    str(len(key_data)) + ";\n")


if __name__ == "__main__":
    main()
