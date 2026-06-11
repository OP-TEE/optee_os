CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

CFG_QCOM_QFPROM_FUSEPROV ?= $(if $(filter y,$(CFG_INSECURE)),n,y)

_qcom_fuseprov_deps = $(if $(filter y,$(CFG_QCOM_QFPROM_FUSEPROV)),y,n)
CFG_QCOM_CMD_DB ?= $(_qcom_fuseprov_deps)
CFG_QCOM_RPMH_CLIENT ?= $(_qcom_fuseprov_deps)
CFG_QCOM_QFPROM ?= $(_qcom_fuseprov_deps)
