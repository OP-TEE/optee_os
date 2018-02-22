PLATFORM_FLAVOR ?= ls1021atwr

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_16550_UART,y)
$(call force,CFG_PM_STUBS,y)

ifeq ($(PLATFORM_FLAVOR),ls1021atwr)
include core/arch/arm/cpu/cortex-a7.mk
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif

ifeq ($(PLATFORM_FLAVOR),ls1021aqds)
include core/arch/arm/cpu/cortex-a7.mk
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif

ifeq ($(PLATFORM_FLAVOR),ls1012ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
endif

ifeq ($(PLATFORM_FLAVOR),ls1043ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
endif

ifeq ($(PLATFORM_FLAVOR),ls1046ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
endif

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
