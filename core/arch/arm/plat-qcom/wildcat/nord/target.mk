# Nord (SA8797P / Oryon) OP-TEE platform.

# Threads are expensive in OP-TEE, so they don't have
# to be same as number of cores.
$(call force,CFG_TEE_CORE_NB_CORE,18)

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_QCOM_PAS_AUTH ?= y
CFG_PAS_MD_SLOTS ?= 8
CFG_RESERVED_VASPACE_SIZE ?= (64 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
