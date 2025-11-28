# Default CPU core for Corstone1000 platform; override for other cores (e.g. cortex-a320)
arm64-platform-cpuarch ?= cortex-a35
include core/arch/arm/cpu/$(arm64-platform-cpuarch).mk

PLATFORM_FLAVOR ?= mps3

$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_PSCI_ARM64,y)
$(call force,CFG_DT,y)
$(call force,CFG_EXTERNAL_DTB_OVERLAY,y)

$(call force,CFG_CORE_SEL1_SPMC,y)
$(call force,CFG_CORE_FFA,y)
$(call force,CFG_SECURE_PARTITION,y)

$(call force,CFG_GIC,y)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)

CFG_WITH_STATS ?= y
CFG_WITH_ARM_TRUSTED_FW ?= y

CFG_TEE_CORE_NB_CORE ?= 1
CFG_TZDRAM_START ?= 0x02002000

# TEE_RAM (OP-TEE kernel + DATA) + TA_RAM
CFG_TZDRAM_SIZE  ?= 0x360000
CFG_SHMEM_START  ?= 0x86000000
CFG_SHMEM_SIZE   ?= 0x00200000

CFG_DDR_SIZE ?= 0x7f000000
CFG_DT_ADDR ?= 0x82100000
CFG_DTB_MAX_SIZE ?= 0x100000
CFG_CORE_HEAP_SIZE ?= 131072
