ifeq ($(CFG_MARVELL_CRYPTO_DRIVER),y)
# Enable Marvell eHSM crypto engine
$(call force,CFG_MARVELL_EHSM_CRYPTO,y)

ifneq (,$(filter $(PLATFORM_FLAVOR),cn10ka cn10kb cnf10ka cnf10kb))
$(call force,CFG_MARVELL_EHSM_CN10K,y)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),cn20ka cnf20ka))
$(call force,CFG_MARVELL_EHSM_CN20K,y)

# eHSM crypto engine context store/load support
$(call force,CFG_EHSM_CONTEXT_STORE_SUPPORT,y)
endif

# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)

CFG_CRYPTO_DRIVER_DEBUG ?= 0
endif
