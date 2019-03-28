cflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -Os

srcs-y += stubbed.c
srcs-y += tomcrypt.c
srcs-$(call cfg-one-enabled, CFG_CRYPTO_MD5 CFG_CRYPTO_SHA1 CFG_CRYPTO_SHA224 \
			     CFG_CRYPTO_SHA256 CFG_CRYPTO_SHA384 \
			     CFG_CRYPTO_SHA512) += hash.c
