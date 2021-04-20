ifneq (,$(filter ${PLATFORM_FLAVOR},tc0 tc1))
include core/arch/arm/cpu/cortex-armv8-0.mk
platform-debugger-arm := 1
endif

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_GENERIC_BOOT,y)
ifeq ($(CFG_CORE_SEL2_SPMC),y)
$(call force,CFG_GIC,n)
$(call force,CFG_ARM_GICV3,n)
else
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
endif
$(call force,CFG_PL011,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)

ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

ifneq (,$(filter ${PLATFORM_FLAVOR},tc0 tc1))
CFG_TEE_CORE_NB_CORE = 8

ifeq ($(CFG_CORE_SEL1_SPMC),y)
CFG_TZDRAM_START ?= 0xfd000000
CFG_TZDRAM_SIZE  ?= 0x02000000
else ifeq ($(CFG_CORE_SEL2_SPMC),y)
CFG_TZDRAM_START ?= 0xfd281000
CFG_TZDRAM_SIZE  ?= 0x01d7f000
else
CFG_TZDRAM_START ?= 0xff000000
CFG_TZDRAM_SIZE  ?= 0x01000000
endif

CFG_SHMEM_START  ?= 0xfce00000
CFG_SHMEM_SIZE   ?= 0x00200000
endif
