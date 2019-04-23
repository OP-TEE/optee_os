incdirs-y += include

subdirs-$(CFG_LS) += hal/ls
subdirs-$(CFG_MX6)$(CFG_MX7)$(CFG_MX7ULP) += hal/imx_6_7
subdirs-$(CFG_IMX8MQ)$(CFG_IMX8MM) += hal/imx_8m
subdirs-y += utils

srcs-y += caam_pwr.c
srcs-y += caam_ctrl.c
srcs-y += caam_jr.c
srcs-y += caam_rng.c
srcs-y += caam_desc.c
subdirs-$(CFG_CRYPTO_HASH_HW) += hash
subdirs-$(CFG_CRYPTO_CIPHER_HW) += cipher

