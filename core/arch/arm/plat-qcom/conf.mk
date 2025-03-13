# Qualcomm platform support

PLATFORM_FLAVOR ?= sc7280

$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_ARM64_PA_BITS,40)
$(call force,CFG_DRIVERS_CLK,y)
$(call force,CFG_DRIVERS_CLK_DT,y)
$(call force,CFG_DRIVERS_QCOM_CLK,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
ta-targets = ta_arm64
supported-ta-targets ?= ta_arm64

CFG_DT ?= n
CFG_DTB_MAX_SIZE ?= 0x40000
CFG_NUM_THREADS ?= 8

ifeq ($(PLATFORM_FLAVOR),sc7280)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GENI_UART,y)

CFG_TZDRAM_START ?= 0x1c120000
CFG_TZDRAM_SIZE  ?= 0x00ee0000
CFG_SHMEM_START  ?= 0x1d000000
CFG_SHMEM_SIZE   ?= 0x00400000

CFG_EARLY_CONSOLE ?= y

CFG_TEE_CORE_LOG_LEVEL ?= 2
endif
