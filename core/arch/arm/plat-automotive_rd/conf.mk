PLATFORM_FLAVOR ?= rdaspen

ifeq ($(PLATFORM_FLAVOR),rd1ae)
# RD-1 AE is based on Neoverse V3AE CPU, but there is
# no compiler support for it yet. Use Neoverse V2 until
# it becomes available.
include core/arch/arm/cpu/neoverse-v2.mk

endif

ifeq ($(PLATFORM_FLAVOR),rdaspen)
# RD-Aspen is based on Cortex-A720AE.
# Cortex-A720AE is not supported in GCC 14.2, hence using Cortex-A720 instead.
# TODO: Update this once the GCC supports cpu variant Cortex-A720AE.
arm32-platform-cpuarch			:= cortex-a720
arm64-platform-cpuarch			:= cortex-a720
include core/arch/arm/cpu/cortex-armv9.mk

CFG_CORE_CLUSTER_SHIFT			:= 2
CFG_CORE_THREAD_SHIFT			:= 0
endif

# ARM debugger needs this
platform-cflags-debug-info		= -gdwarf-4
platform-aflags-debug-info		= -gdwarf-4

CFG_CORE_HEAP_SIZE			?= 0x32000
CFG_CORE_RESERVED_SHM			?= n
CFG_CORE_SEL1_SPMC			?= y
CFG_TZDRAM_SIZE				?= 0x00400000
CFG_TZDRAM_START			?= 0xFFC00000
CFG_WITH_ARM_TRUSTED_FW			?= y

$(call force,CFG_ARM64_core,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CORE_ARM64_PA_BITS,42)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_TEE_CORE_NB_CORE,16)
