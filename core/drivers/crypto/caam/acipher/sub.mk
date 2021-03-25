incdirs-y += ../include

srcs-$(CFG_NXP_CAAM_RSA_DRV) += caam_rsa.c
srcs-y += caam_prime.c caam_math.c
srcs-$(CFG_NXP_CAAM_ECC_DRV) += caam_ecc.c
