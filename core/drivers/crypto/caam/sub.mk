incdirs-y += include

subdirs-y += hal
subdirs-y += utils

srcs-y += caam_pwr.c
srcs-y += caam_ctrl.c
srcs-y += caam_jr.c
srcs-y += caam_rng.c
srcs-y += caam_desc.c
subdirs-$(CFG_CRYPTO_HASH_HW) += hash

