PLATFORM_FLAVOR ?= stm32mp157c

include core/arch/arm/cpu/cortex-a7.mk
ta-targets = ta_arm32

$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_INIT_CNTVOFF,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)

CFG_TZSRAM_START ?= 0x2ffc0000
CFG_TZSRAM_SIZE  ?= 0x00040000
CFG_TZDRAM_START ?= 0xfe000000
CFG_TZDRAM_SIZE  ?= 0x01e00000
CFG_SHMEM_SIZE   ?= 0x00200000
CFG_SHMEM_START  ?= 0xffe00000

CFG_WITH_PAGER		?= y
CFG_WITH_LPAE		?= y
CFG_WITH_STACK_CANARIES	?= y

CFG_STM32_UART ?= y

# Default enable the test facitilites
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y
