ifeq ($(CFG_MARVELL_EHSM_CRYPTO),y)
srcs-y += mrvl_ehsm_cryp.c

srcs-y += ehsm/ehsm.c ehsm/ehsm-aes.c
incdirs-y += ehsm/include
endif

