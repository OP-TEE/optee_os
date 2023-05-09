ifeq ($(CFG_VERSAL_CRYPTO_DRIVER),y)
# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)

CFG_CRYPTO_DRIVER_DEBUG ?= 0
$(call force,CFG_CRYPTO_DRV_ACIPHER,y)
$(call force,CFG_CRYPTO_DRV_ECC,y)
$(call force,CFG_CRYPTO_DRV_RSA,y)
$(call force,CFG_CRYPTO_DRV_AUTHENC,y)

endif
