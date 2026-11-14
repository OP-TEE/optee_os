CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM ?= y
endif

CFG_QCOM_TLMM ?= y

CFG_QCOM_HWKM ?= y

# cff7d191-7ca0-4784-af13-48223b9a4fbe identifies the PAS early TA. Embed it
# so its normal-world PIL/PAS service is available before the REE filesystem.
CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_RESERVED_VASPACE_SIZE ?= (60 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
CFG_QCOM_PAS_AUTH ?= y
endif

ifeq ($(CFG_QCOM_PAS_AUTH),y)
$(call force,CFG_QCOM_FUSE_PTA,y)
endif

ifneq ($(filter y,$(CFG_QCOM_QFPROM_FUSEPROV) $(CFG_QCOM_FUSE_PTA)),)
$(call force,CFG_QCOM_QFPROM,y)
endif

$(call force,CFG_QCOM_CSRNG,y)
CFG_WITH_SOFTWARE_PRNG ?= n