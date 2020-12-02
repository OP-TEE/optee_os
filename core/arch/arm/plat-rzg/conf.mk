PLATFORM_FLAVOR ?= hihope_rzg2m

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as RZ/G2 platform
#    does not provide DTB to OP-TEE. Also, there is no
#    publicly available documentation on integrated
#    hardware RNG, so we can't use it either.
# 2. OP-TEE crashes during boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)

ifeq ($(PLATFORM_FLAVOR),ek874)
$(call force,CFG_TEE_CORE_NB_CORE,2)
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2m)
$(call force,CFG_TEE_CORE_NB_CORE,6)
# RZ/G2M have 6 cores for 2 clusters, but the number isn't contiguous.
# One cluster has ids 0, 1, other has ids 3, 4, 5, 6.
# CFG_CORE_CLUSTER_SHIFT will process to make the right numbering.
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2n)
$(call force,CFG_TEE_CORE_NB_CORE,2)
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2h)
$(call force,CFG_TEE_CORE_NB_CORE,8)
endif

CFG_TZDRAM_START ?= 0x44100000
CFG_TZDRAM_SIZE ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_DT ?= y
