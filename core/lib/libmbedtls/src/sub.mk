srcs-y += tee_lmd_provider.c
cflags-tee_lmd_provider.c-y += -Wno-unused-parameter

# For mbedtls
cflags-y += -Icore/lib/libmbedtls/src/mbedtls/include
cflags-y += -D'MBEDTLS_CONFIG_FILE="mbedtls_config.h"'
cflags-y += -D_FILE_OFFSET_BITS=64 -Wno-old-style-definition \
	-Wno-redundant-decls -Wno-switch-default \
	-Wno-unused-parameter -Wno-strict-aliasing \
	-Wno-unused-function

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
# Cipher
srcs-$(CFG_CRYPTO_AES) += mbedtls/library/aes.c
srcs-$(CFG_CRYPTO_GCM) += mbedtls/library/aesni.c
srcs-$(CFG_CRYPTO_GCM) += mbedtls/library/arc4.c
srcs-$(CFG_CRYPTO_GCM) += mbedtls/library/blowfish.c
srcs-$(CFG_CRYPTO_CCM) += mbedtls/library/ccm.c
srcs-$(CFG_CRYPTO_GCM) += mbedtls/library/camellia.c
srcs-$(CFG_CRYPTO_DES) += mbedtls/library/des.c
srcs-$(CFG_CRYPTO_GCM) += mbedtls/library/gcm.c
srcs-$(_CFG_CRYPTO_WITH_CIPHER) += mbedtls/library/cipher.c \
			mbedtls/library/cipher_wrap.c

#MAC
srcs-$(CFG_CRYPTO_CMAC) += mbedtls/library/cmac.c
