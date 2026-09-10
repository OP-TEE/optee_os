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
        help='Prefix for the public key exponent and modulus in c file')
    parser.add_argument(
        '--out', required=True,
        help='Name of c file for the public key')
    parser.add_argument('--key', required=True, help='Name of key file')

    return parser.parse_args()


def emit_array(f, name, data):
    import array

    f.write("const uint8_t " + name + "[] = {\n")
    i = 0
    # An empty initializer isn't allowed in C so emit a dummy byte for
    # unused arrays, the matching size tells that the array is unused.
    for x in array.array("B", data if data else b'\x00'):
        f.write("0x" + '{0:02x}'.format(x) + ",")
        i = i + 1
        if i % 8 == 0:
            f.write("\n")
        else:
            f.write(" ")
    f.write("};\n")


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

    exponent = 0
    modulus = b''
    curve = 0
    ecc_size = 0
    ecc_xy = b''

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
        modulus = key.public_numbers().n.to_bytes(key.key_size >> 3, 'big')
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(
                'Unsupported curve {}, '.format(key.curve.name) +
                'only NIST P-256 (secp256r1) is supported.')

        main_algo = TEE_MAIN_ALGO_ECDSA
        curve = TEE_ECC_CURVE_NIST_P256
        ecc_size = (key.curve.key_size + 7) // 8
        ecc_xy = (key.public_numbers().x.to_bytes(ecc_size, 'big') +
                  key.public_numbers().y.to_bytes(ecc_size, 'big'))
    else:
        raise ValueError('Unsupported key type {}'.format(type(key).__name__))

    with open(args.out, 'w') as f:
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")
        f.write("const uint32_t " + args.prefix + "_main_algo = 0x" +
                '{0:02x}'.format(main_algo) + ";\n\n")
        f.write("const uint32_t " + args.prefix + "_exponent = " +
                str(exponent) + ";\n\n")
        emit_array(f, args.prefix + "_modulus", modulus)
        f.write("const size_t " + args.prefix + "_modulus_size = " +
                str(len(modulus)) + ";\n\n")
        f.write("const uint32_t " + args.prefix + "_ecc_curve = " +
                str(curve) + ";\n\n")
        emit_array(f, args.prefix + "_ecc_xy", ecc_xy)
        f.write("const size_t " + args.prefix + "_ecc_size = " +
                str(ecc_size) + ";\n")


if __name__ == "__main__":
    main()
