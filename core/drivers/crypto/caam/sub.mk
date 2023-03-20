incdirs-y += include

subdirs-y += hal
subdirs-y += utils

srcs-y += caam_pwr.c
srcs-y += caam_ctrl.c
srcs-y += caam_jr.c
srcs-y += caam_rng.c
srcs-y += caam_desc.c
srcs-$(CFG_NXP_CAAM_SM_DRV) += caam_sm.c
srcs-y += caam_key.c
subdirs-$(call cfg-one-enabled, CFG_NXP_CAAM_HASH_DRV CFG_NXP_CAAM_HMAC_DRV) += hash
subdirs-$(call cfg-one-enabled, CFG_NXP_CAAM_CIPHER_DRV CFG_NXP_CAAM_CMAC_DRV) += cipher
subdirs-y += acipher
subdirs-y += blob
subdirs-$(CFG_NXP_CAAM_MP_DRV) += mp
