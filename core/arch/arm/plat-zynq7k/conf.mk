PLATFORM_FLAVOR ?= zc702

include core/arch/arm/cpu/cortex-a9.mk

$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CDNS_UART,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

# Xilinx Zynq-7000's Cortex-A9 core has been configured with Non-maskable FIQ
# (NMFI) support. This means that FIQ interrupts cannot be used in system
# designs as atomic contexts cannot mask FIQ out.
$(call force,CFG_CORE_WORKAROUND_ARM_NMFI,y)

CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_ENABLE_SCTLR_RR ?= y
