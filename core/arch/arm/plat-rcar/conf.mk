PLATFORM_FLAVOR ?= generic_dt

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)

CFG_TZDRAM_START ?= 0x44100000
CFG_TZDRAM_SIZE	 ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_PTA ?= y
supported-ta-targets = ta_arm64

CFG_DT ?= y
