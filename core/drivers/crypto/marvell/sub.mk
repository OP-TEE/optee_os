srcs-$(CFG_CRYPTO_DRV_AUTHENC) += authenc.c

ifeq ($(CFG_MARVELL_EHSM_CRYPTO),y)
srcs-y += mrvl_ehsm_cryp.c

ifneq (,$(filter $(PLATFORM_FLAVOR),cn10ka cn10kb cnf10ka cnf10kb))
srcs-y += cn10k/ehsm.c cn10k/ehsm-aes.c
incdirs-y += cn10k/include
endif
endif

