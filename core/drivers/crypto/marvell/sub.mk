srcs-$(CFG_CRYPTO_DRV_AUTHENC) += authenc.c

ifeq ($(CFG_MARVELL_EHSM_CRYPTO),y)
srcs-y += mrvl_ehsm_cryp.c

srcs-y += ehsm/ehsm.c ehsm/ehsm-aes.c
incdirs-y += ehsm/include

ifneq (,$(filter $(PLATFORM_FLAVOR),cn10ka cn10kb cnf10ka cnf10kb))
$(call force,CFG_MARVELL_EHSM_CN10K,y)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR), cn20ka cnf20ka))
$(call force,CFG_MARVELL_EHSM_CN20K,y)

# eHSM crypto engine context store/load support
$(call force,CFG_EHSM_CONTEXT_STORE_SUPPORT,y)
endif
endif

