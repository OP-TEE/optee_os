PLATFORM_FLAVOR ?= ls1021atwr
PLATFORM_FLAVOR_$(PLATFORM_FLAVOR) := y

arm32-platform-cpuarch		:= cortex-a7
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_16550_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_BOOT_SYNC_CPU,y)

ta-targets = ta_arm32

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
