#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright Amazon.com Inc. or its affiliates
#
import typing

import boto3

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    AsymmetricSignatureContext,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.padding import (
    AsymmetricPadding,
    PKCS1v15,
    PSS,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
)


class _RSAPrivateKeyInKMS(RSAPrivateKey):

    def __init__(self, arn):
        self.arn = arn
        self.client = boto3.client('kms')
        response = self.client.get_public_key(KeyId=self.arn)

        # Parse public key
        self.public_key = serialization.load_der_public_key(
                response['PublicKey'])

    @property
    def key_size(self):
        return self.public_key.key_size

    def public_key(self) -> RSAPublicKey:
        return self.public_key

    def sign(self, data: bytes, padding: AsymmetricPadding,
             algorithm: typing.Union[asym_utils.Prehashed,
                                     hashes.HashAlgorithm]
             ) -> bytes:
        if isinstance(algorithm, asym_utils.Prehashed):
            message_type = 'DIGEST'
        else:
            message_type = 'RAW'

        if isinstance(padding, PSS):
            signing_alg = 'RSASSA_PSS_'
        elif isinstance(padding, PKCS1v15):
            signing_alg = 'RSASSA_PKCS1_V1_5_'
        else:
            raise TypeError("Unsupported padding")

        if (isinstance(algorithm._algorithm, hashes.SHA256) or
                isinstance(algorithm, hashes.SHA256)):
            signing_alg += 'SHA_256'
        elif (isinstance(algorithm._algorithm, hashes.SHA384) or
                isinstance(algorithm, hashes.SHA384)):
            signing_alg += 'SHA_384'
        elif (isinstance(algorithm._algorithm, hashes.SHA512) or
                isinstance(algorithm, hashes.SHA512)):
            signing_alg += 'SHA_512'
        else:
            raise TypeError("Unsupported hashing algorithm")

        response = self.client.sign(
                KeyId=self.arn, Message=data,
                MessageType=message_type,
                SigningAlgorithm=signing_alg)

        return response['Signature']

    # No need to implement these functions so we raise an exception
    def signer(
        self, padding: AsymmetricPadding, algorithm: hashes.HashAlgorithm
    ) -> AsymmetricSignatureContext:
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError

    def private_numbers(self) -> RSAPrivateNumbers:
        raise NotImplementedError

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption
    ) -> bytes:
        raise NotImplementedError
