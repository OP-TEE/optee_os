ifeq ($(CFG_LS),y)
CAAM_HAL_DIR = ls
endif
ifeq ($(filter y, $(CFG_MX6) $(CFG_MX7) $(CFG_MX7ULP)),y)
CAAM_HAL_DIR = imx_6_7
endif
ifeq ($(filter y, $(CFG_IMX8MQ) $(CFG_IMX8MM) $(CFG_IMX8MN)),y)
CAAM_HAL_DIR = imx_8m
endif

subdirs-y += common
subdirs-y += $(CAAM_HAL_DIR)
