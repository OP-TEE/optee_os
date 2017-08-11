srcs-y += tee_lmd_provider.c

# Random bit generator configure
CFG_MBEDTLS_CTR_PRNG ?= y
CFG_MBEDTLS_HMAC_PRNG ?= n

# For mbedtls
cflags-y += -Icore/lib/libmbedtls/src/mbedtls/include
cppflags-y += -D'MBEDTLS_CONFIG_FILE="mbedtls_config.h"'
cflags-y += -Wno-switch-default -Wno-unused-parameter

# Hashes
srcs-y += mbedtls/library/md5.c \
		mbedtls/library/sha1.c \
		mbedtls/library/sha256.c \
		mbedtls/library/sha512.c \
		mbedtls/library/md_wrap.c \
		mbedtls/library/md.c

# Cipher
srcs-y += mbedtls/library/aes.c \
		mbedtls/library/des.c \
		mbedtls/library/cipher.c \
		mbedtls/library/cipher_wrap.c

# DRBG
srcs-y += mbedtls/library/entropy.c \
		mbedtls/library/ctr_drbg.c \
		mbedtls/library/hmac_drbg.c

# MAC
srcs-y += mbedtls/library/cmac.c

# Asymmetric ciphers
srcs-y += mbedtls/library/bignum.c \
		mbedtls/library/oid.c \
		mbedtls/library/asn1parse.c \
		mbedtls/library/asn1write.c \
		mbedtls/library/pk_wrap.c \
		mbedtls/library/pk.c \
		mbedtls/library/rsa.c
