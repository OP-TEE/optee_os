cflags-y += -Wno-unused-parameter

srcs-$(CFG_CRYPTO_AES) += aes.c
srcs-$(CFG_CRYPTO_AES) += aes_tab.c
srcs-$(CFG_CRYPTO_DES) += des.c
