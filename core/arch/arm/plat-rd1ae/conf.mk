# RD-1 AE is based on Neoverse V3AE CPU, but there is
# no compiler support for it yet. Use Neoverse V2 until
# it becomes available.
include core/arch/arm/cpu/neoverse-v2.mk

# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-4
platform-aflags-debug-info = -gdwarf-4

$(call force,CFG_ARM64_core,y)

$(call force,CFG_ARM_GICV3,y)

CFG_CORE_SEL1_SPMC      ?= y
CFG_WITH_ARM_TRUSTED_FW	?= y
CFG_CORE_RESERVED_SHM   ?= n

$(call force,CFG_GIC,y)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_CORE_ARM64_PA_BITS,42)
$(call force,CFG_TEE_CORE_NB_CORE,16)

CFG_CORE_HEAP_SIZE ?= 0x32000

CFG_TZDRAM_START ?= 0xFFC00000
CFG_TZDRAM_SIZE  ?= 0x00400000
