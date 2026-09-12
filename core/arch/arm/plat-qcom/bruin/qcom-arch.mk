# BRUIN family (QCM2290 / QRB2210, SM4125 Agatti): 4x Cortex-A53, GIC-500
# (GICv3), RPM (not RPMh).

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_NUM_THREADS ?= 4

$(call force,CFG_ARM_GICV3,y)

CFG_QCOM_CSRNG ?= n
CFG_WITH_SOFTWARE_PRNG ?= y

# Hard ':=' (not '?='): CFG_TZDRAM_START must equal TF-A's BL32_BASE. A
# conditional assignment can lose to an earlier family default, linking OP-TEE
# for an address other than the one TF-A enters BL32 at, which hangs the
# BL31->BL32 handoff.
CFG_TZDRAM_START := 0x40200000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
CFG_TA_RAM_VA_SIZE ?= 0x100000
CFG_TZDRAM_SIZE ?= (CFG_TEE_RAM_VA_SIZE + CFG_TA_RAM_VA_SIZE)
