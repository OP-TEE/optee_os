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
$(call force,CFG_SCMI_MSG_DRIVERS,y)
$(call force,CFG_SCMI_MSG_CLOCK,y)
$(call force,CFG_SCMI_MSG_RESET_DOMAIN,y)
$(call force,CFG_SCMI_MSG_SMT,y)
$(call force,CFG_SCMI_MSG_SMT_FASTCALL_ENTRY,y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-512M)),)
CFG_TZDRAM_START ?= 0xde000000
CFG_SHMEM_START  ?= 0xdfe00000
CFG_DRAM_SIZE    ?= 0x20000000
endif

CFG_TZSRAM_START ?= 0x2ffc0000
CFG_TZSRAM_SIZE  ?= 0x0003f000
CFG_STM32MP1_SCMI_SHM_BASE ?= 0x2ffff000
CFG_STM32MP1_SCMI_SHM_SIZE ?= 0x00001000
CFG_TZDRAM_START ?= 0xfe000000
CFG_TZDRAM_SIZE  ?= 0x01e00000
CFG_SHMEM_START  ?= 0xffe00000
CFG_SHMEM_SIZE   ?= 0x00200000
CFG_DRAM_SIZE    ?= 0x40000000

CFG_TEE_CORE_NB_CORE ?= 2
CFG_WITH_PAGER ?= y
CFG_WITH_LPAE ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_MMAP_REGIONS ?= 23

ifeq ($(CFG_EMBED_DTB_SOURCE_FILE),)
# Some drivers mandate DT support
$(call force,CFG_STM32_I2C,n)
$(call force,CFG_STPMIC1,n)
endif

CFG_STM32_BSEC ?= y
CFG_STM32_ETZPC ?= y
CFG_STM32_GPIO ?= y
CFG_STM32_I2C ?= y
CFG_STM32_RNG ?= y
CFG_STM32_RNG ?= y
CFG_STM32_UART ?= y
CFG_STPMIC1 ?= y

ifeq ($(CFG_STPMIC1),y)
$(call force,CFG_STM32_I2C,y)
$(call force,CFG_STM32_GPIO,y)
endif

# Default enable some test facitilites
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y

# Default disable some support for pager memory size constraint
CFG_TEE_CORE_DEBUG ?= n
CFG_UNWIND ?= n
CFG_LOCKDEP ?= n
CFG_CORE_ASLR ?= n

# Non-secure UART and GPIO/pinctrl for the output console
CFG_WITH_NSEC_GPIOS ?= y
CFG_WITH_NSEC_UARTS ?= y
# UART instance used for early console (0 disables early console)
CFG_STM32_EARLY_CONSOLE_UART ?= 4
