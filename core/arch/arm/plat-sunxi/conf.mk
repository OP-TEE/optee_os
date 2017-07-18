include core/arch/arm/cpu/cortex-a15.mk

core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_ARM32_core,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_SUNXI_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_GIC,y)

ta-targets = ta_arm32

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_NUM_THREADS ?= 4
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
