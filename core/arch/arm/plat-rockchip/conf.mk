PLATFORM_FLAVOR ?= rk322x

ifeq ($(PLATFORM_FLAVOR),rk322x)
include ./core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
endif

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)
$(call force,CFG_8250_UART,y)

CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
