PLATFORM_FLAVOR ?= b2260

include core/arch/arm/cpu/cortex-a9.mk

core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_ARM32_core,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
$(call force,CFG_PL310,y)
$(call force,CFG_CACHE_API,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_WITH_LPAE,n)
$(call force,CFG_GIC,y)

ta-targets = ta_arm32

CFG_WITH_PAGER ?= n
CFG_BOOT_SYNC_CPU ?= y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
CFG_STIH_UART ?= y

ifeq ($(PLATFORM_FLAVOR),b2260)
CFG_PL310_LOCKED ?= y
else
CFG_PL310_LOCKED ?= n
endif
