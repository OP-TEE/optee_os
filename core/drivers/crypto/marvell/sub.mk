srcs-$(CFG_CRYPTO_DRV_AUTHENC) += authenc.c
srcs-$(CFG_CRYPTO_DRV_CIPHER) += cipher.c

ifeq ($(CFG_MARVELL_EHSM_CRYPTO),y)
srcs-y += mrvl_ehsm_cryp.c

ifneq (,$(filter $(PLATFORM_FLAVOR),cn10ka cn10kb cnf10ka cnf10kb))
srcs-y += cn10k/ehsm.c cn10k/ehsm-aes.c
incdirs-y += cn10k/include
endif
ifneq (,$(filter $(PLATFORM_FLAVOR), cn20ka cnf20ka))

# eHSM crypto engine Contest store/load support
$(call force,CFG_EHSM_CONTEXT_STORE_SUPPORT,y)

srcs-y += cn20k/ehsm.c cn20k/ehsm-aes.c
incdirs-y += cn20k/include
endif
endif

