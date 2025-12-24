# Qualcomm platform support

PLATFORM_FLAVOR ?= kodiak

$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_ARM64_PA_BITS,40)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_QCOM_GENI_UART,y)

ta-targets = ta_arm64
supported-ta-targets ?= ta_arm64

ifneq (,$(filter $(PLATFORM_FLAVOR),kodiak lemans))
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)

$(call force,CFG_QCOM_RAMBLUR_PIMEM_V3,y)
CFG_QCOM_RAMBLUR_TA_WINDOW_ID ?= 2

$(call force,CFG_QCOM_PRNG,y)

CFG_TZDRAM_START ?= 0x1c300000
CFG_TEE_RAM_VA_SIZE ?= 0x200000
CFG_TA_RAM_VA_SIZE ?= 0x1c00000
CFG_TZDRAM_SIZE  ?= (CFG_TEE_RAM_VA_SIZE + CFG_TA_RAM_VA_SIZE)
CFG_NUM_THREADS  ?= 8
endif
