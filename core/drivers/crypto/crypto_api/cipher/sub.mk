
srcs-y += cipher.c

ifeq ($(CFG_CRYPTO_CTS_FROM_CRYPTOLIB), y)
cppflags-cipher.c-y += -DCFG_CRYPTO_DRV_CTS
endif
