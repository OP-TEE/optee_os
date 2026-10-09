srcs-$(CFG_CRYPTO_DRV_AUTHENC) += authenc.c
srcs-$(CFG_CRYPTO_DRV_CIPHER) += cipher.c

ifeq ($(CFG_MARVELL_EHSM_CRYPTO),y)
srcs-y += mrvl_ehsm_cryp.c

srcs-y += ehsm/ehsm.c ehsm/ehsm-aes.c
incdirs-y += ehsm/include
endif

