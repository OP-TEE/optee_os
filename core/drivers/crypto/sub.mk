global-incdirs-$(CFG_CRYPTO_DRIVER) += crypto_api/include

subdirs-$(CFG_CRYPTO_DRIVER) += crypto_api

subdirs-$(CFG_NXP_CAAM) += caam

subdirs-$(CFG_NXP_SE05X) += se050

subdirs-$(CFG_STM32_CRYPTO_DRIVER) += stm32

subdirs-$(CFG_ASPEED_CRYPTO_DRIVER) += aspeed

subdirs-$(CFG_VERSAL_CRYPTO_DRIVER) += versal

subdirs-$(CFG_HISILICON_CRYPTO_DRIVER) += hisilicon
