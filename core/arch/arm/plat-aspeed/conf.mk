PLATFORM_FLAVOR ?= ast2600

ifeq ($(PLATFORM_FLAVOR),ast2600)
include core/arch/arm/cpu/cortex-a7.mk

$(call force,CFG_8250_UART,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)

CFG_DRAM_BASE ?= 0x80000000
CFG_DRAM_SIZE ?= 0x40000000

CFG_TZDRAM_START ?= 0xb0000000
CFG_TZDRAM_SIZE ?= 0x1000000

CFG_CORE_RESERVED_SHM ?= n

arm32-platform-cflags += -mfpu=vfpv3-d16
else ifeq ($(PLATFORM_FLAVOR),ast2700)
include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_8250_UART,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GIC,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)

CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)

CFG_DRAM_BASE ?= 0x400000000
CFG_DRAM_SIZE ?= 0x40000000

CFG_TZDRAM_START ?= 0x430080000
CFG_TZDRAM_SIZE ?= 0x1000000

CFG_CORE_RESERVED_SHM ?= n

supported-ta-targets = ta_arm64
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif
