PLATFORM_FLAVOR ?= cyclonev

include core/arch/arm/cpu/cortex-a9.mk

$(call force,CFG_TEE_CORE_NB_CORE,1)

#RR: debug added.
$(call force,CFG_TEE_CORE_DEBUG,y)
$(call force,CFG_TEE_CORE_LOG_LEVEL,3)
$(call force,CFG_NUM_THREADS,1)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_GIC,y)
$(call force,CFG_8250_UART,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
$(call force,CFG_CORE_ASLR,y)

CFG_BOOT_SYNC_CPU ?= n
CFG_BOOT_SECONDARY_REQUEST ?= n
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_ENABLE_SCTLR_RR ?= y
