PLATFORM_FLAVOR ?= rzn1

include core/arch/arm/cpu/cortex-a7.mk

$(call force,CFG_ARM32_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_16550_UART,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_PAGER,n)
$(call force,CFG_GIC,y)
$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_TA_FLOAT_SUPPORT,n)

ta-targets = ta_arm32

CFG_TZDRAM_START ?= 0x88000000
CFG_TZDRAM_SIZE ?= 0x00A00000
CFG_SHMEM_START ?= 0x87C00000
CFG_SHMEM_SIZE  ?= 0x00400000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000

CFG_NUM_THREADS ?= 4
CFG_NS_ENTRY_ADDR ?= 0x87A00000

CFG_BOOT_CM3 ?= y
