flavor_dts_file-257F_EV1 = stm32mp257f-ev1.dts

flavorlist-MP25 = $(flavor_dts_file-257F_EV1)

ifneq ($(PLATFORM_FLAVOR),)
ifeq ($(flavor_dts_file-$(PLATFORM_FLAVOR)),)
$(error Invalid platform flavor $(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= $(flavor_dts_file-$(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= stm32mp257f-ev1.dts

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-MP25)),)
$(call force,CFG_STM32MP25,y)
endif

ifneq ($(CFG_STM32MP25),y)
$(error STM32 Platform must be defined)
endif

include core/arch/arm/cpu/cortex-armv8-0.mk
supported-ta-targets ?= ta_arm64

$(call force,CFG_ARM64_core,y)
$(call force,CFG_DRIVERS_CLK,y)
$(call force,CFG_DRIVERS_CLK_DT,y)
$(call force,CFG_DRIVERS_GPIO,y)
$(call force,CFG_DRIVERS_PINCTRL,y)
$(call force,CFG_DT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_HALT_CORES_ON_PANIC_SGI,15)
$(call force,CFG_INIT_CNTVOFF,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_WITH_LPAE,y)

CFG_TZDRAM_START ?= 0x82000000
CFG_TZDRAM_SIZE  ?= 0x02000000

# Support DDR ranges up to 8GBytes (address range: 0x80000000 + DDR size)
CFG_CORE_LARGE_PHYS_ADDR ?= y
CFG_CORE_ARM64_PA_BITS ?= 34

CFG_CORE_HEAP_SIZE ?= 262144
CFG_CORE_RESERVED_SHM ?= n
CFG_DTB_MAX_SIZE ?= 262144
CFG_HALT_CORES_ON_PANIC ?= y
CFG_MMAP_REGIONS ?= 30
CFG_NUM_THREADS ?= 5
CFG_TEE_CORE_NB_CORE ?= 2

CFG_STM32_FMC ?= y
CFG_STM32_GPIO ?= y
CFG_STM32_HPDMA ?= y
CFG_STM32_HSEM ?= y
CFG_STM32_IPCC ?= y
CFG_STM32_RIF ?= y
CFG_STM32_RIFSC ?= y
CFG_STM32_RNG ?= y
CFG_STM32_UART ?= y

# Default enable some test facitilites
CFG_ENABLE_EMBEDDED_TESTS ?= y
CFG_WITH_STATS ?= y

# Default disable ASLR
CFG_CORE_ASLR ?= n

# UART instance used for early console (0 disables early console)
CFG_STM32_EARLY_CONSOLE_UART ?= 2

# Default disable external DT support
CFG_EXTERNAL_DT ?= n

# Default enable HWRNG PTA support
CFG_HWRNG_PTA ?= y
ifeq ($(CFG_HWRNG_PTA),y)
$(call force,CFG_STM32_RNG,y,Required by CFG_HWRNG_PTA)
$(call force,CFG_WITH_SOFTWARE_PRNG,n,Required by CFG_HWRNG_PTA)
CFG_HWRNG_QUALITY ?= 1024
endif
