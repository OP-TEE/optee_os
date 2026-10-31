# Nord (SA8797P / Oryon) OP-TEE platform.

# Threads are expensive in OP-TEE, so they don't have
# to be same as number of cores.
$(call force,CFG_TEE_CORE_NB_CORE,18)

# DARE-TZ secure memory regions. DARE is another in-line
# memory encryption IP similar to pIMEM but on wildcat arch
# it is setup by TME root-of-trust, no specific driver needed
# in OP-TEE for that.
CFG_TZDRAM_START ?= 0xBC280000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x07B80000

# Only the security fuses are read on this target; the fuse-blow driver and the
# provisioning flow built on it are not supported.
CFG_QCOM_FUSE_BLOW ?= n
CFG_QCOM_QFPROM_FUSEPROV ?= n

ifeq ($(CFG_QCOM_QFPROM_FUSEPROV),y)
$(call force,CFG_QCOM_CMD_DB,y)
$(call force,CFG_QCOM_RPMH_CLIENT,y)
$(call force,CFG_QCOM_QFPROM,y)
endif

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_PAS_MD_SLOTS ?= 8
CFG_RESERVED_VASPACE_SIZE ?= (64 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
CFG_QCOM_PAS_AUTH ?= y
endif

ifeq ($(CFG_QCOM_PAS_AUTH),y)
CFG_PAS_MD_SLOTS = 8
$(call force,CFG_QCOM_FUSE_PTA,y)
$(call force,CFG_QCOM_QFPROM,y)
endif

CFG_QCOM_CMD_DB ?= y
CFG_QCOM_RPMH_CLIENT ?= y
ifeq ($(CFG_QCOM_RPMH_CLIENT),y)
$(call force,CFG_QCOM_CMD_DB,y)
endif
