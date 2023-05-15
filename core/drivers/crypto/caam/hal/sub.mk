ifeq ($(CFG_LS),y)
CAAM_HAL_DIR = ls
endif
ifeq ($(filter y, $(CFG_MX6) $(CFG_MX7) $(CFG_MX7ULP)),y)
CAAM_HAL_DIR = imx_6_7
endif
ifeq ($(filter y, $(CFG_MX8MQ) $(CFG_MX8MM) $(CFG_MX8MN) $(CFG_MX8MP)),y)
CAAM_HAL_DIR = imx_8m
endif
ifeq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX)),y)
CAAM_HAL_DIR = imx_8q
endif
ifeq ($(filter y, $(CFG_MX8ULP)),y)
CAAM_HAL_DIR = imx_8ulp
endif


subdirs-y += common
subdirs-y += $(CAAM_HAL_DIR)
