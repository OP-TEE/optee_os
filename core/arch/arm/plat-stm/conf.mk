PLATFORM_FLAVOR ?= orly2

arm32-platform-cpuarch		:= cortex-a9
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_ARM32_core,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
$(call force,CFG_PL310,y)
$(call force,CFG_CACHE_API,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_BOOT_SYNC_CPU,y)

ta-targets = ta_arm32

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
CFG_TEE_GDB_BOOT ?= y

include $(platform-dir)/system_config.mk
