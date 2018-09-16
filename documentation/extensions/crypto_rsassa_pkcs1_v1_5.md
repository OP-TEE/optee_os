# PKCS#1 v1.5 RSASSA without hash OID

This extension adds `TEE_ALG_RSASSA_PKCS1_V1_5` to allow signing and verifying
messages with `RSASSA-PKCS1-v1_5` ([RFC 3447](https://tools.ietf.org/html/rfc3447#section-8.2))
without including the OID of the hash in the signature. Trusted Applications
should include `<tee_api_defines_extensions.h>` to import the definitions.

The extension can be used by defining `CFG_CRYPTO_RSASSA_NA1`.

# API extensions

The TEE Internal Core API was extended with a new algorithm descriptor.

Algorithm                   | Possible Modes
:---------------------------|:--------------
TEE_ALG_RSASSA_PKCS1_V1_5 | TEE_MODE_SIGN <br> TEE_MODE_VERIFY

Algorithm                      | Identifier
:------------------------------|:----------
TEE_ALG_RSASSA_PKCS1_V1_5 | 0xF0000830
