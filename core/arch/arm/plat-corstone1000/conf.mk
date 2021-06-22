PLATFORM_FLAVOR ?= mps3

$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_ENABLE_SCTLR_RR,n)
$(call force,CFG_ENABLE_SCTLR_Z,n)

arm64-platform-cpuarch := cortex-a35
arm64-platform-cflags += -mcpu=$(arm64-platform-cpuarch)
arm64-platform-aflags += -mcpu=$(arm64-platform-cpuarch)
platform-flavor-armv8 := 1

$(call force,CFG_GIC,y)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

$(call force,CFG_ARM64_core,y)

CFG_WITH_STATS ?= y

CFG_WITH_ARM_TRUSTED_FW ?= y
CFG_WITH_LPAE ?=y

CFG_TEE_CORE_NB_CORE = 1
CFG_TZDRAM_START ?= 0x02002000
CFG_TZDRAM_SIZE  ?= 0x000FE000
CFG_TEE_RAM_VA_SIZE ?= 0x00AF000
CFG_SHMEM_START  ?= 0x86000000
CFG_SHMEM_SIZE   ?= 0x00200000

CFG_DDR_SIZE ?= 0x80000000
CFG_DT_ADDR ?= 0x82100000
CFG_DTB_MAX_SIZE ?= 0x100000

$(call force,CFG_PSCI_ARM64,y)
$(call force,CFG_DT,y)
$(call force,CFG_EXTERNAL_DTB_OVERLAY,y)
