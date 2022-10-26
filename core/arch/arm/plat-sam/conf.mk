PLATFORM_FLAVOR ?= sama5d27_som1_ek

flavor_dts_file-sama5d2xult = at91-sama5d2_xplained.dts
flavor_dts_file-sama5d2_xplained = at91-sama5d2_xplained.dts
flavor_dts_file-sama5d27_som1_ek = at91-sama5d27_som1_ek.dts
flavor_dts_file-sama5d27_wlsom1_ek = at91-sama5d27_wlsom1_ek.dts
flavor_dts_file-sama7g54_ek = at91-sama7g54_ek.dts

ifeq ($(PLATFORM_FLAVOR),sama5d2xult)
$(warning "sama5d2xult is deprecated, please use sama5d2_xplained")
endif

ifeq ($(flavor_dts_file-$(PLATFORM_FLAVOR)),)
$(error Invalid platform flavor $(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= $(flavor_dts_file-$(PLATFORM_FLAVOR))

ifeq ($(PLATFORM_FLAVOR),sama7g54_ek)
include core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_SAMA7G5,y)
$(call force,CFG_GIC,y)
$(call force,CFG_TZC400,y)
else
include core/arch/arm/cpu/cortex-a5.mk
$(call force,CFG_SAMA5D2,y)
$(call force,CFG_ATMEL_SAIC,y)
$(call force,CFG_PL310,y)
endif

$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_ATMEL_UART,y)
$(call force,CFG_ATMEL_TCB,y)
$(call force,CFG_NO_SMP,y)
$(call force,CFG_AT91_MATRIX,y)
$(call force,CFG_DRIVERS_CLK,y)
$(call force,CFG_DRIVERS_CLK_DT,y)
$(call force,CFG_DRIVERS_CLK_FIXED,y)
$(call force,CFG_DRIVERS_SAM_CLK,y)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_CORE_HAS_GENERIC_TIMER,n)

# These values are forced because of matrix configuration for secure area.
# When modifying these, always update matrix settings in
# matrix_configure_slave_h64mx().
ifeq ($(CFG_SAMA7G5),y)
$(call force,CFG_TZDRAM_START,0x60000000)
endif
ifeq ($(CFG_SAMA5D2),y)
$(call force,CFG_TZDRAM_START,0x20000000)
endif
$(call force,CFG_TZDRAM_SIZE,0x800000)

# This value is forced because these feature aren't used by SAM platforms.
$(call force,CFG_EXTERNAL_DT,n)
$(call force,CFG_CORE_DYN_SHM,n)

CFG_MMAP_REGIONS ?= 24

CFG_SHMEM_START  ?= ($(CFG_TZDRAM_START) + 0x1000000)
CFG_SHMEM_SIZE   ?= 0x400000

CFG_SCMI_SHMEM_START  ?= ($(CFG_TZDRAM_START) + 0x1400000)
CFG_SCMI_SHMEM_SIZE   ?= 0x1000

CFG_TEE_RAM_VA_SIZE ?= 0x100000

# Device tree related configuration
CFG_DT_ADDR ?= ($(CFG_TZDRAM_START) + 0x1500000)
CFG_GENERATE_DTB_OVERLAY ?= y

CFG_WITH_SOFTWARE_PRNG ?= n
CFG_ATMEL_TRNG ?= y
ifeq ($(CFG_ATMEL_TRNG),y)
CFG_HWRNG_PTA ?= y
$(call force,CFG_HWRNG_QUALITY,1024)
endif

CFG_ATMEL_RSTC ?= y
CFG_ATMEL_SHDWC ?= y

CFG_ATMEL_PM ?= y

ifeq ($(CFG_ATMEL_PM),y)
# Suspend mode to be used on PSCI suspend call
# 0 = STANDBY
# 1 = ULP0
# 2 = ULP0 Fast
# 3 = ULP1
# 4 = BACKUP
CFG_ATMEL_PM_SUSPEND_MODE ?= 0

$(call force,CFG_ATMEL_SHDWC,y)
$(call force,CFG_PM_ARM32,y)
endif

CFG_WDT ?= y
CFG_WDT_SM_HANDLER ?= y
ifeq ($(CFG_WDT_SM_HANDLER),y)
CFG_WDT_SM_HANDLER_ID := 0x2000500
endif
CFG_ATMEL_WDT ?= y

CFG_DRIVERS_RTC ?= y
CFG_RTC_PTA ?= y
CFG_ATMEL_RTC ?= y
CFG_ATMEL_PIOBU ?= y

ifeq ($(PLATFORM_FLAVOR),sama5d27_wlsom1_ek)
CFG_DRIVERS_GPIO ?= y
CFG_DRIVERS_I2C ?= y
CFG_ATMEL_I2C ?= y
CFG_DRIVERS_PINCTRL ?= y
CFG_ATMEL_PIO ?= y
endif

# SCMI related configuration
CFG_SCMI_PTA ?= y

CFG_SCMI_MSG_DRIVERS ?= y
ifeq ($(CFG_SCMI_MSG_DRIVERS),y)
$(call force,CFG_SCMI_MSG_SMT,y)
$(call force,CFG_SCMI_MSG_CLOCK,y)
$(call force,CFG_SCMI_MSG_USE_CLK,y)
$(call force,CFG_SCMI_MSG_SMT_FASTCALL_ENTRY,y)
endif

CFG_DRIVERS_NVMEM ?= y
ifeq ($(CFG_SAMA7G5),y)
CFG_ATMEL_SFC ?= n
CFG_NVMEM_DIE_ID ?= n
CFG_NVMEM_HUK ?= n
else
CFG_ATMEL_SFC ?= y
CFG_NVMEM_DIE_ID ?= y
CFG_NVMEM_HUK ?= y
endif
