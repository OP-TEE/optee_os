CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_DIAG_LOG ?= $(if $(filter y,$(CFG_TEE_CORE_DEBUG)),y,n)

CFG_QCOM_QFPROM_FUSEPROV ?= $(if $(filter y,$(CFG_INSECURE)),n,y)

_qcom_fuseprov_deps = $(if $(filter y,$(CFG_QCOM_QFPROM_FUSEPROV)),y,n)
CFG_QCOM_CMD_DB ?= $(_qcom_fuseprov_deps)
CFG_QCOM_RPMH_CLIENT ?= $(_qcom_fuseprov_deps)
CFG_QCOM_QFPROM ?= $(_qcom_fuseprov_deps)

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
