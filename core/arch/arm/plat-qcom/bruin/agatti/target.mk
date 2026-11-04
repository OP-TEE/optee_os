# ':=' because TZDRAM must match TF-A's BL32_BASE/BL32_SIZE, not the
# architecture default. Less TA RAM than this makes nested TA sessions fail
# with TEEC_ERROR_OUT_OF_MEMORY.
CFG_TZDRAM_START := 0x46200000
CFG_TEE_RAM_VA_SIZE := 0x400000
CFG_TA_RAM_VA_SIZE := 0x2100000

$(call force,CFG_QCOM_CSRNG,y)
CFG_WITH_SOFTWARE_PRNG ?= n

CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
# PAS subsystems map their controller windows at runtime from the reserved VA
# pool (never released), in 2 MiB blocks.
CFG_RESERVED_VASPACE_SIZE ?= (48 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
