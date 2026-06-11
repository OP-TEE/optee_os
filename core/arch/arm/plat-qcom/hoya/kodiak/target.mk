CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_DIAG_LOG ?= $(if $(filter y,$(CFG_TEE_CORE_DEBUG)),y,n)

CFG_QCOM_QFPROM_FUSEPROV ?= $(if $(filter y,$(CFG_INSECURE)),n,y)

_qcom_fuseprov_deps = $(if $(filter y,$(CFG_QCOM_QFPROM_FUSEPROV)),y,n)
CFG_QCOM_CMD_DB ?= $(_qcom_fuseprov_deps)
CFG_QCOM_RPMH_CLIENT ?= $(_qcom_fuseprov_deps)
CFG_QCOM_QFPROM ?= $(_qcom_fuseprov_deps)

CFG_QCOM_PAS_PTA ?= y
# Kodiak requires MX voltage rail workaround for QFPROM fuse blowing
$(call force,CFG_QFPROM_MX_RAIL_WA,y)

ifeq ($(CFG_QCOM_PAS_PTA),y)
# Increase late mappings to cover all PAS resources
CFG_RESERVED_VASPACE_SIZE ?= (60 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
