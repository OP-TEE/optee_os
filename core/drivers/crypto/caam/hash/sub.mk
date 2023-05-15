incdirs-y += ../include

srcs-y += caam_hash.c
srcs-$(CFG_NXP_CAAM_HMAC_DRV) += caam_hash_mac.c
