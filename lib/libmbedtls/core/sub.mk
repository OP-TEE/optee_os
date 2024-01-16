cppflags-y += -DMBEDTLS_ALLOW_PRIVATE_ACCESS
srcs-y += mbed_helpers.c
srcs-y += tomcrypt.c
srcs-$(call cfg-one-enabled, CFG_CRYPTO_MD5 CFG_CRYPTO_SHA1 CFG_CRYPTO_SHA224 \
			     CFG_CRYPTO_SHA256 CFG_CRYPTO_SHA384 \
			     CFG_CRYPTO_SHA512) += hash.c

ifeq ($(CFG_CRYPTO_AES),y)
srcs-y += aes.c
srcs-$(CFG_CRYPTO_ECB) += aes_ecb.c
srcs-$(CFG_CRYPTO_CBC) += aes_cbc.c
srcs-$(CFG_CRYPTO_CTR) += aes_ctr.c
endif
ifeq ($(CFG_CRYPTO_DES),y)
srcs-$(CFG_CRYPTO_ECB) += des_ecb.c
srcs-$(CFG_CRYPTO_ECB) += des3_ecb.c
srcs-$(CFG_CRYPTO_CBC) += des_cbc.c
srcs-$(CFG_CRYPTO_CBC) += des3_cbc.c
endif

srcs-$(CFG_CRYPTO_HMAC) += hmac.c
srcs-$(CFG_CRYPTO_CMAC) += cmac.c

ifneq ($(CFG_CRYPTO_DSA),y)
srcs-$(call cfg-one-enabled, CFG_CRYPTO_RSA  CFG_CRYPTO_DH \
			     CFG_CRYPTO_ECC) += bignum.c
endif
srcs-$(CFG_CRYPTO_RSA) += rsa.c
srcs-$(CFG_CRYPTO_DH) += dh.c
srcs-$(CFG_CRYPTO_ECC) += ecc.c
srcs-$(CFG_CRYPTO_SM2_DSA) += sm2-dsa.c
srcs-$(CFG_CRYPTO_SM2_KEP) += sm2-kep.c
srcs-$(CFG_CRYPTO_SM2_PKE) += sm2-pke.c
