# ':=' because TZDRAM must match TF-A's BL32_BASE/BL32_SIZE, not the
# architecture default. Less TA RAM than this makes nested TA sessions fail
# with TEEC_ERROR_OUT_OF_MEMORY.
CFG_TZDRAM_START := 0x46200000
CFG_TEE_RAM_VA_SIZE := 0x400000
CFG_TA_RAM_VA_SIZE := 0x2100000

$(call force,CFG_QCOM_CSRNG,y)
CFG_WITH_SOFTWARE_PRNG ?= n