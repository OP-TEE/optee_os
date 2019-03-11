cppflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -DLTC_SMALL_CODE
cppflags-lib-y += -DLTC_RSA_CRT_HARDENING -DLTC_RSA_BLINDING
cflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -Os

global-incdirs-y += include

subdirs-y += src

srcs-$(_CFG_CRYPTO_WITH_HASH) += hash.c
srcs-$(CFG_CRYPTO_HMAC) += hmac.c
srcs-$(CFG_CRYPTO_CMAC) += cmac.c
srcs-$(CFG_CRYPTO_ECB) += ecb.c
srcs-$(CFG_CRYPTO_CBC) += cbc.c
srcs-$(CFG_CRYPTO_CTR) += ctr.c
srcs-$(CFG_CRYPTO_XTS) += xts.c
srcs-$(CFG_CRYPTO_CCM) += ccm.c
srcs-$(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB) += gcm.c
srcs-$(CFG_CRYPTO_DSA) += dsa.c
srcs-$(CFG_CRYPTO_ECC) += ecc.c
srcs-$(CFG_CRYPTO_RSA) += rsa.c
