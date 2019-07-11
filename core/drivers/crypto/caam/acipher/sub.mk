COMMON_HAL = ../hal/common

incdirs-y += $(COMMON_HAL)/registers

incdirs-y += ../include

srcs-$(CFG_CRYPTO_ECC_HW) += caam_ecc.c

