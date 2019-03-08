cppflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -DLTC_SMALL_CODE
cppflags-lib-y += -DLTC_RSA_CRT_HARDENING -DLTC_RSA_BLINDING
cflags-lib-$(CFG_CRYPTO_SIZE_OPTIMIZATION) += -Os

global-incdirs-y += include

subdirs-y += src

srcs-$(_CFG_CRYPTO_WITH_HASH) += hash.c
