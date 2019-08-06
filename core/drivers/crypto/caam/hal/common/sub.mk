incdirs-y += ../../include
incdirs-y += ../$(CAAM_HAL_DIR)
incdirs-y += .

ifeq ($(CFG_CAAM_DT),y)
srcs-y += hal_cfg_dt.c
else
srcs-y += hal_cfg.c
endif
srcs-y += hal_rng.c
srcs-y += hal_jr.c
srcs-y += hal_ctrl.c
