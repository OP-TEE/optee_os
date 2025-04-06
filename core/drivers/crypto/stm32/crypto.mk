# CFG_STM32_CRYPTO_DRIVER, when enabled, embeds
#       STM32 HW cryptographic support and OP-TEE Crypto Driver.
# CFG_STM32_CRYP, when enabled, embeds
#       STM32 CRYP module support,
#       CIPHER Crypto Driver,
#       AUTHENC Crypto Driver.

ifeq ($(CFG_STM32_CRYPTO_DRIVER),y)

$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(call cfg-one-enabled, CFG_STM32_CRYP CFG_STM32_SAES),y)
$(call force,CFG_CRYPTO_DRV_CIPHER,y,Mandated by CFG_STM32_CRYP)
endif

ifeq ($(CFG_STM32_CRYP),y)
$(call force,CFG_CRYPTO_DRV_AUTHENC,y,Mandated by CFG_STM32_CRYP)
endif

ifeq ($(CFG_STM32_HASH),y)
$(call force,CFG_CRYPTO_DRV_HASH,y,Mandated by CFG_STM32_HASH)
$(call force,CFG_CRYPTO_DRV_MAC,y,Mandated by CFG_STM32_HASH)
endif

ifeq ($(CFG_STM32_PKA),y)
$(call force,CFG_CRYPTO_DRV_ECC,y,Mandated by CFG_STM32_PKA)
$(call force,CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_STM32_PKA)
endif

endif # CFG_STM32_CRYPTO_DRIVER
