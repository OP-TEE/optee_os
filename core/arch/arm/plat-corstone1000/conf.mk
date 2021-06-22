PLATFORM_FLAVOR ?= mps3

# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2

$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_ENABLE_SCTLR_RR,n)
$(call force,CFG_ENABLE_SCTLR_Z,n)

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

arm64-platform-cpuarch := cortex-a35
arm64-platform-cflags += -mcpu=$(arm64-platform-cpuarch)
arm64-platform-aflags += -mcpu=$(arm64-platform-cpuarch)

CFG_WITH_STATS ?= y
CFG_WITH_ARM_TRUSTED_FW ?= y

CFG_TEE_CORE_NB_CORE ?= 1
CFG_TZDRAM_START ?= 0x02002000

# TEE_RAM (OPTEE kernel + DATA) + TA_RAM = 3MB
CFG_TZDRAM_SIZE  ?= 0x300000
CFG_SHMEM_START  ?= 0x86000000
CFG_SHMEM_SIZE   ?= 0x00200000

CFG_DDR_SIZE ?= 0x7f000000
CFG_DT_ADDR ?= 0x82100000
CFG_DTB_MAX_SIZE ?= 0x100000
CFG_CORE_HEAP_SIZE ?= 131072
