ifeq ($(CFG_MARVELL_CRYPTO_DRIVER),y)
# Enable Marvell eHSM crypto engine
$(call force,CFG_MARVELL_EHSM_CRYPTO,y)

# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)

CFG_CRYPTO_DRIVER_DEBUG ?= 0
endif
