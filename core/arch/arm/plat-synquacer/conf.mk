PLATFORM_FLAVOR ?= developerbox

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_PL011,y)

include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,24)
CFG_NUM_THREADS ?= 8
CFG_TZDRAM_START ?= 0xfc000000
CFG_TZDRAM_SIZE ?= 0x03c00000
CFG_SHMEM_START ?= 0xffc00000
CFG_SHMEM_SIZE ?= 0x00400000

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_ARM64_core,y)
supported-ta-targets = ta_arm64

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
