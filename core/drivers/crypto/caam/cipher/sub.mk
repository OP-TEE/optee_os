incdirs-y += ../include

srcs-y += caam_cipher.c
srcs-y += caam_cipher_xts.c
srcs-$(CFG_NXP_CAAM_CMAC_DRV) += caam_cipher_mac.c
