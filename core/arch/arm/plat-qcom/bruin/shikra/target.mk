CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM_FUSEPROV ?= y
endif

ifeq ($(CFG_QCOM_QFPROM_FUSEPROV),y)
$(call force,CFG_QCOM_QFPROM,y)
endif

ifeq ($(CFG_QCOM_QFPROM),y)
# Fuse blowing requires the supply rail to be voted through RPMH.
$(call force,CFG_QCOM_RPMH_CLIENT,y)
$(call force,CFG_QCOM_CMD_DB,y)
endif
