CFG_NUM_THREADS ?= 16
CFG_CRYPTO_WITH_CE ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
# Override default size of emulated TrustZone protected SRAM, 384 kB
CFG_CORE_TZSRAM_EMUL_SIZE ?= 393216
# Overrides default in mk/config.mk with 96 kB
CFG_CORE_HEAP_SIZE ?= 98304

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_HI16XX_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_HI16XX_RNG,y)
endif

# 32-bit flags
arm32-platform-cpuarch		:= cortex-a57
arm32-platform-cflags		+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags		+= -mcpu=$(arm32-platform-cpuarch)
core_arm32-platform-aflags	+= -mfpu=neon

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

