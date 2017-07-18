PLATFORM_FLAVOR ?= zc702

include core/arch/arm/cpu/cortex-a9.mk

core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_ARM32_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CDNS_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

ta-targets = ta_arm32

CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
