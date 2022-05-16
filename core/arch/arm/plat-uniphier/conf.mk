PLATFORM_FLAVOR ?= ld20

include core/arch/arm/cpu/cortex-armv8-0.mk

ifeq ($(PLATFORM_FLAVOR),ld20)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
CFG_DRAM0_BASE      ?= 0x80000000
CFG_DRAM0_SIZE      ?= 0xc0000000
CFG_DRAM0_RSV_SIZE  ?= 0x02000000
endif

ifeq ($(PLATFORM_FLAVOR),ld11)
$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_DRAM0_BASE      ?= 0x80000000
CFG_DRAM0_SIZE      ?= 0x40000000
CFG_DRAM0_RSV_SIZE  ?= 0x02000000
endif

CFG_TZDRAM_START    ?= (CFG_DRAM0_BASE + 0x01080000)
CFG_TZDRAM_SIZE     ?= 0x00E00000
CFG_SHMEM_START     ?= (CFG_DRAM0_BASE + 0x00E00000)
CFG_SHMEM_SIZE      ?= 0x00200000
CFG_TEE_RAM_VA_SIZE ?= 0x00100000

# 32-bit flags
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_8250_UART,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)

ta-targets = ta_arm32

ifeq ($(CFG_ARM64_core),y)
ta-targets += ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_NUM_THREADS ?= 4
CFG_CRYPTO_WITH_CE ?= y
