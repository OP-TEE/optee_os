PLATFORM_FLAVOR ?= stm32mp157

# 1GB and 512MB DDR target do not locate secure DDR at the same place.
#
flavorlist-1G = stm32mp157c-ev1.dts stm32mp157c-ed1.dts
flavorlist-512M = stm32mp157c-dk2.dts

include core/arch/arm/cpu/cortex-a7.mk

$(call force,CFG_BOOT_SECONDARY_REQUEST,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_INIT_CNTVOFF,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-512M)),)
CFG_TZDRAM_START ?= 0xde000000
CFG_SHMEM_START  ?= 0xdfe00000
endif

CFG_TZSRAM_START ?= 0x2ffc0000
CFG_TZSRAM_SIZE  ?= 0x00040000
CFG_TZDRAM_START ?= 0xfe000000
CFG_TZDRAM_SIZE  ?= 0x01e00000
CFG_SHMEM_START  ?= 0xffe00000
CFG_SHMEM_SIZE   ?= 0x00200000

CFG_TEE_CORE_NB_CORE ?= 2
CFG_WITH_PAGER ?= y
CFG_WITH_LPAE ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_MMAP_REGIONS ?= 23

CFG_STM32_UART ?= y

# Default enable some test facitilites
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y
# Non-secure UART for the output console
CFG_WITH_NSEC_UARTS ?= y
# UART instance used for early console (0 disables early console)
CFG_STM32_EARLY_CONSOLE_UART ?= 4
