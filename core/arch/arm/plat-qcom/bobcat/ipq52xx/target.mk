$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_NUM_THREADS ?= 4

# GICv2 can't route individual interrupts to EL3: delegate TF-A-owned ones
$(call force,CFG_QCOM_GICV2_EL3_INTR_DELEGATION,y)

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)

CFG_TZDRAM_START ?= 0x87D80000
CFG_TZDRAM_SIZE ?= 0x280000
CFG_TEE_RAM_VA_SIZE ?= 0x280000

$(call force,CFG_QCOM_CSRNG,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)

CFG_HWRNG_PTA ?= y
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_RATE ?= 0

# Enable ICE filesystem-encryption PTA
CFG_QCOM_ICE_PTA ?= y
