srcs-$(CFG_CRYPTO_SHA224) += sha224.c

ifeq ($(CFG_CRYPTO_SHA256_ARM32_CE),y)
srcs-y += sha256_arm32_ce.c
srcs-y += sha256_arm32_ce_a32.S
else
srcs-$(CFG_CRYPTO_SHA256) += sha256.c
endif

srcs-$(CFG_CRYPTO_SHA384) += sha384.c
srcs-$(CFG_CRYPTO_SHA512) += sha512.c
