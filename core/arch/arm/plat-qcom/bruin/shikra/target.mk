CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM ?= y
endif

ifeq ($(CFG_QCOM_QFPROM_FUSEPROV),y)
$(call force,CFG_QCOM_QFPROM,y)
endif

# ICB RPM depends on both CLK_CFG and RPM_CLIENT
ifeq ($(CFG_QCOM_CLK_CFG),y)
ifeq ($(CFG_QCOM_RPM_CLIENT),y)
CFG_QCOM_ICB_RPM ?= y
endif
endif

ifeq ($(CFG_QCOM_ICB_RPM),y)
# u_data.c defines 21 routes.
CFG_QCOM_ICB_MAX_CLIENTS = 21
endif
