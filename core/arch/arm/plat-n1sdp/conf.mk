include core/arch/arm/cpu/cortex-armv8-0.mk

ifeq ($(CFG_SCTLR_ALIGNMENT_CHECK),y)
$(call force,CFG_TA_ARM32_NO_HARD_FLOAT_SUPPORT,y)
else
$(call force,CFG_SCTLR_ALIGNMENT_CHECK,n)
endif

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)

$(call force,CFG_GIC,y)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

$(call force,CFG_CORE_SEL1_SPMC,y)
$(call force,CFG_CORE_FFA,y)
$(call force,CFG_SECURE_PARTITION,y)

CFG_ARM64_core ?= y
CFG_ARM_GICV3 ?= y

CFG_DEBUG_INFO ?= y
CFG_TEE_CORE_LOG_LEVEL ?= 4

# ARM debugger needs this
platform-cflags-debug-info ?= -gdwarf-4
platform-aflags-debug-info ?= -gdwarf-4

CFG_CORE_SEL1_SPMC	?= y
CFG_WITH_ARM_TRUSTED_FW	?= y

CFG_CORE_HEAP_SIZE ?= 0x32000 # 200kb

CFG_TEE_CORE_NB_CORE ?= 4
CFG_TZDRAM_START ?= 0x08000000
CFG_TZDRAM_SIZE  ?= 0x02008000

CFG_SHMEM_START  ?= 0x83000000
CFG_SHMEM_SIZE   ?= 0x00210000
