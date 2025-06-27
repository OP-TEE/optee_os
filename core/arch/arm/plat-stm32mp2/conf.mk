flavor_dts_file-215F_DK = stm32mp215f-dk.dts
flavor_dts_file-257F_EV1 = stm32mp257f-ev1.dts

flavorlist-MP21 = $(flavor_dts_file-215F_DK)
flavorlist-MP25 = $(flavor_dts_file-257F_EV1)

# List of all DTS for this PLATFORM
ALL_DTS = $(flavorlist-MP21) $(flavorlist-MP25)

ifneq ($(PLATFORM_FLAVOR),)
ifeq ($(flavor_dts_file-$(PLATFORM_FLAVOR)),)
$(error Invalid platform flavor $(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= $(flavor_dts_file-$(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= stm32mp257f-ev1.dts

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-MP21)),)
$(call force,CFG_STM32MP21,y)
endif
ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-MP25)),)
$(call force,CFG_STM32MP25,y)
endif

# CFG_STM32MP2x switches are exclusive.
# - CFG_STM32MP21 is enabled for STM32MP21x-* targets
# - CFG_STM32MP25 is enabled for STM32MP25x-* targets (default)
ifeq ($(CFG_STM32MP21),y)
$(call force,CFG_STM32MP25,n)
else
$(call force,CFG_STM32MP21,n)
$(call force,CFG_STM32MP25,y)
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
$(call force,CFG_SCMI_SCPFW_PRODUCT,stm32mp2)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_STM32_SHARED_IO,y)
$(call force,CFG_STM32_STGEN,y)
$(call force,CFG_STM32MP_CLK_CORE,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_WITH_LPAE,y)

ifeq ($(CFG_STM32MP21),y)
$(call force,CFG_STM32MP21_CLK,y)
$(call force,CFG_STM32MP21_RSTCTRL,y)
else
$(call force,CFG_STM32MP25_CLK,y)
$(call force,CFG_STM32MP25_RSTCTRL,y)
endif

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
ifeq ($(CFG_STM32MP21),y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
endif
CFG_TEE_CORE_NB_CORE ?= 2
CFG_STM32MP_OPP_COUNT ?= 3

CFG_STM32_EXTI ?= y
CFG_STM32_FMC ?= y
CFG_STM32_GPIO ?= y
CFG_STM32_HPDMA ?= y
CFG_STM32_HSEM ?= y
CFG_STM32_IAC ?= y
CFG_STM32_IPCC ?= y
CFG_STM32_OMM ?= y
CFG_STM32_RIF ?= y
CFG_STM32_RIFSC ?= y
CFG_STM32_RISAB ?= y
CFG_STM32_RISAF ?= y
CFG_STM32_RNG ?= y
CFG_STM32_RTC ?= y
CFG_STM32_SERC ?= y
CFG_STM32_TAMP ?= y
CFG_STM32_UART ?= y

CFG_SCMI_PTA ?= y
CFG_SCMI_SCPFW ?= n
CFG_SCMI_SCPFW_FROM_DT ?= y
CFG_SCMI_SERVER_CLOCK_CONSUMER ?= y
CFG_SCMI_SERVER_RESET_CONSUMER ?= y
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

# Enable reset control
ifeq ($(CFG_STM32MP21_RSTCTRL),y)
$(call force,CFG_DRIVERS_RSTCTRL,y)
$(call force,CFG_STM32_RSTCTRL,y)
endif
ifeq ($(CFG_STM32MP25_RSTCTRL),y)
$(call force,CFG_DRIVERS_RSTCTRL,y)
$(call force,CFG_STM32_RSTCTRL,y)
endif

# Optional behavior upon receiving illegal access events
CFG_STM32_PANIC_ON_IAC_EVENT ?= y
ifeq ($(CFG_TEE_CORE_DEBUG),y)
CFG_STM32_PANIC_ON_SERC_EVENT ?= n
else
CFG_STM32_PANIC_ON_SERC_EVENT ?= y
endif

# Default enable firewall support
CFG_DRIVERS_FIREWALL ?= y
ifeq ($(call cfg-one-enabled, CFG_STM32_RISAB CFG_STM32_RIFSC),y)
$(call force,CFG_DRIVERS_FIREWALL,y)
endif

# Enable RTC
ifeq ($(CFG_STM32_RTC),y)
$(call force,CFG_DRIVERS_RTC,y)
endif

ifeq ($(CFG_STM32_SERC),y)
$(call force,CFG_EXTERNAL_ABORT_PLAT_HANDLER,y)
endif
