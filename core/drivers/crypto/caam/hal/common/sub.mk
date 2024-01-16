incdirs-y += ../../include
incdirs-y += ../$(CAAM_HAL_DIR)
incdirs-y += .

srcs-$(CFG_DT) += hal_cfg_dt.c
srcs-y += hal_cfg.c
srcs-y += hal_rng.c
srcs-y += hal_jr.c
srcs-y += hal_ctrl.c
srcs-$(CFG_NXP_CAAM_SM_DRV) += hal_sm.c
