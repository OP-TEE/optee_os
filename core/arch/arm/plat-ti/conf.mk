PLATFORM_FLAVOR ?= dra7xx

CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y
CFG_WITH_SOFTWARE_PRNG ?= n
CFG_SECURE_DATA_PATH ?= y

ifeq ($(CFG_SECURE_DATA_PATH),y)
CFG_TEE_SDP_MEM_SIZE ?= 0x00400000
else
CFG_TEE_SDP_MEM_SIZE ?= 0x0
endif

$(call force,CFG_8250_UART,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
ifeq ($(PLATFORM_FLAVOR),am43xx)
CFG_WITH_SOFTWARE_PRNG = y
$(call force,CFG_NO_SMP,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_PM_ARM32,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
include core/arch/arm/cpu/cortex-a9.mk
else
CFG_OTP_SUPPORT ?= y
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
include core/arch/arm/cpu/cortex-a15.mk
endif
$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_GIC,y)
ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_DRA7_RNG,y)
endif

ta-targets = ta_arm32
