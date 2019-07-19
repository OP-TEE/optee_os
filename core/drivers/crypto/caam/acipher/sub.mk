COMMON_HAL = ../hal/common

incdirs-y += $(COMMON_HAL)/registers

incdirs-y += ../include
incdirs-y += include

srcs-$(CFG_CRYPTO_ECC_HW) += caam_ecc.c
srcs-$(CFG_CRYPTO_RSA_HW) += caam_rsa.c caam_prime.c caam_math.c
