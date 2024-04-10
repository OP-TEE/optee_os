ifeq ($(CFG_HISILICON_ACC_V3), y)
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

$(call force, CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)

ifeq ($(CFG_HISILICON_ACC_V3), y)
$(call force, CFG_CRYPTO_DRV_DH,y,Mandated by CFG_HISILICON_ACC_V3)
endif

endif
