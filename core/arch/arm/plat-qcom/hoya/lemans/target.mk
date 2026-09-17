CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM_FUSEPROV ?= y
endif

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
# PAS subsystems map their controller windows at runtime from the reserved VA
# pool (never released). The six DSP windows total ~146.5 MB; the 60 MB default
# fits only one, so reserve 256 MB with headroom.
CFG_RESERVED_VASPACE_SIZE ?= (256 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
CFG_QCOM_PAS_AUTH ?= y
endif

CFG_QCOM_HWKM ?= y

ifeq ($(CFG_QCOM_PAS_AUTH),y)
$(call force,CFG_QCOM_FUSE_PTA,y)
CFG_PAS_MD_SLOTS = 8
# This chip's OEM_CONFIG2 fuse row has a per-root-cert hash function
# select bit; targets without it always use SHA-384.
$(call force,CFG_QCOM_SEGMENT_HASH_SELECT,y)
# OEM-provisioned multi-root-certificate activation/revocation bitmasks
# (bit N = root cert N), blown to fuses at boot. 0 (default) provisions
# nothing.
CFG_QCOM_MRC_ACTIVATION_LIST ?= 0
CFG_QCOM_MRC_REVOCATION_LIST ?= 0
endif

ifneq ($(filter y,$(CFG_QCOM_QFPROM_FUSEPROV) $(CFG_QCOM_FUSE_PTA)),)
$(call force,CFG_QCOM_QFPROM,y)
endif
