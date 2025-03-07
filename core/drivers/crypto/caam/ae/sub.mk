incdirs-y += ../include

srcs-y += caam_ae.c
srcs-$(CFG_NXP_CAAM_AE_GCM_DRV) += caam_ae_gcm.c
srcs-$(CFG_NXP_CAAM_AE_CCM_DRV) += caam_ae_ccm.c
