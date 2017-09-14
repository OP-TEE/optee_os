srcs-y += tee_lmd_provider.c
cflags-tee_lmd_provider.c-y += -Wno-unused-parameter -Wno-unused-function

# For mbedtls
cflags-y += -Icore/lib/libmbedtls/src/mbedtls/include
cflags-y += -D'MBEDTLS_CONFIG_FILE="mbedtls_config.h"'
cflags-y += -D_FILE_OFFSET_BITS=64 -Wno-old-style-definition \
	-Wno-unused-parameter

# Hashes
srcs-$(CFG_CRYPTO_MD5) += mbedtls/library/md5.c
srcs-$(CFG_CRYPTO_MD2) += mbedtls/library/md2.c
srcs-$(CFG_CRYPTO_MD4) += mbedtls/library/md4.c
srcs-$(CFG_CRYPTO_SHA1) += mbedtls/library/sha1.c
ifneq ($(CFG_CRYPTO_SHA224)_$(CFG_CRYPTO_SHA256),n_n)
srcs-y += mbedtls/library/sha256.c
endif
ifneq ($(CFG_CRYPTO_SHA384)_$(CFG_CRYPTO_SHA512),n_n)
srcs-y += mbedtls/library/sha512.c
endif
srcs-$(CFG_CRYPTO_RIPEMD160) += mbedtls/library/ripemd160.c
srcs-$(_CFG_CRYPTO_WITH_HASH) += mbedtls/library/md.c \
			mbedtls/library/md_wrap.c

# Asymmetric ciphers
srcs-$(_CFG_CRYPTO_WITH_ACIPHER) += mbedtls/library/bignum.c
