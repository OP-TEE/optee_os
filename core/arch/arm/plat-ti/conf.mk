PLATFORM_FLAVOR ?= dra7xx

CFG_WITH_STATS ?= y
CFG_WITH_SOFTWARE_PRNG ?= n

ifeq ($(PLATFORM_FLAVOR),dra7xx)
include core/arch/arm/cpu/cortex-a15.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_OTP_SUPPORT ?= y
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
endif #dra7xx

ifeq ($(PLATFORM_FLAVOR),am57xx)
include core/arch/arm/cpu/cortex-a15.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_OTP_SUPPORT ?= y
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
endif #am57xx

ifeq ($(PLATFORM_FLAVOR),am43xx)
include core/arch/arm/cpu/cortex-a9.mk
$(call force, CFG_TEE_CORE_NB_CORE,1)
CFG_WITH_SOFTWARE_PRNG = y
$(call force,CFG_NO_SMP,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_PM_ARM32,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
endif #am43xx

$(call force,CFG_8250_UART,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_SM_PLATFORM_HANDLER,y)
$(call force,CFG_GIC,y)
ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_DRA7_RNG,y)
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_PTA ?= y
endif
