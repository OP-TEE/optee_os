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

CFG_TZDRAM_START ?= 0x88000000
CFG_TZDRAM_SIZE ?= 0x01000000

CFG_CORE_RESERVED_SHM ?= n
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif
