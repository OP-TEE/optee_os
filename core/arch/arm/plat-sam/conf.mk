PLATFORM_FLAVOR ?= sama5d2xult

include core/arch/arm/cpu/cortex-a5.mk

$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_ATMEL_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
$(call force,CFG_NO_SMP,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_AT91_MATRIX,y)

CFG_WITH_STACK_CANARIES ?= y
