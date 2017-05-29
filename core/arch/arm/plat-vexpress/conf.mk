PLATFORM_FLAVOR ?= qemu_virt

# 32-bit flags
arm32-platform-cpuarch		:= cortex-a15
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

ifeq ($(PLATFORM_FLAVOR),fvp)
platform-flavor-armv8 := 1
platform-debugger-arm := 1
endif
ifeq ($(PLATFORM_FLAVOR),juno)
platform-flavor-armv8 := 1
platform-debugger-arm := 1
endif
ifeq ($(PLATFORM_FLAVOR),qemu_armv8a)
platform-flavor-armv8 := 1
$(call force,CFG_DT,y)
endif


ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
endif

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_HWSUPP_MEM_PERM_WXN,y)
$(call force,CFG_PL011,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y

ifeq ($(PLATFORM_FLAVOR),juno)
CFG_CRYPTO_WITH_CE ?= y
endif

ifeq ($(PLATFORM_FLAVOR),qemu_virt)
ifeq ($(CFG_CORE_SANITIZE_KADDRESS),y)
# CFG_ASAN_SHADOW_OFFSET is calculated as:
# (&__asan_shadow_start - (CFG_TEE_RAM_START / 8)
# This is unfortunately currently not possible to do in make so we have to
# calculate it offline, there's some asserts in
# core/arch/arm/kernel/generic_boot.c to check that we got it right
CFG_ASAN_SHADOW_OFFSET=0xc4e38e0
endif
$(call force,CFG_DT,y)
# SE API is only supported by QEMU Virt platform
CFG_SE_API ?= y
CFG_SE_API_SELF_TEST ?= y
CFG_PCSC_PASSTHRU_READER_DRV ?= y
endif
