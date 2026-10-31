CFG_QCOM_LM_PROFILE ?= n

# Low memory profile: 512 KB of TZDRAM and no user TAs. It has to stay above
# the defaults below, the first assignment wins.
ifeq ($(CFG_QCOM_LM_PROFILE),y)
CFG_TZDRAM_SIZE ?= 0x80000
CFG_TEE_RAM_VA_SIZE ?= 0x80000
CFG_CORE_HEAP_SIZE ?= 0x8000
CFG_NUM_THREADS ?= 2

# Nothing runs at EL0 without user TAs, so there are no user address spaces.
# The page table pool serves those only, 1 is the smallest value that builds.
CFG_WITH_USER_TA ?= n
CFG_PGT_CACHE_ENTRIES ?= 1
CFG_CORE_UNMAP_CORE_AT_EL0 ?= n
CFG_TA_FLOAT_SUPPORT ?= n

CFG_REE_FS ?= n
CFG_CORE_ASLR ?= n
CFG_PREALLOC_RPC_CACHE ?= n

# Random data comes from the CSRNG, nothing else needs a crypto library
CFG_CRYPTO ?= n
endif

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
