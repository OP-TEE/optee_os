PLATFORM_FLAVOR ?= hi3519av100_demo

hi3519av100-flavorlist = hi3519av100_demo hi3519av100_tst

ifneq (,$(filter $(PLATFORM_FLAVOR),$(hi3519av100-flavorlist)))
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_HI3519AV100,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
# Hi3519av100 has got two clusters, one core per cluster
$(call force,CFG_CORE_CLUSTER_SHIFT,0)

$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM32_core,y)
$(call force,CFG_PSCI_ARM32,y)

CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_NUM_THREADS ?= 4
CFG_CRYPTO_WITH_CE ?= y
CFG_NS_ENTRY_ADDR ?= 0x22008000
CFG_CORE_HEAP_SIZE ?= 131072

#
# Hi3519av100 memory map
#
# This is a general memory map for demo board, and for your own board,
# you have to define your own memory map.
#
#  0x4000_0000 [DRAM_LIMIT]
#    other (media memory zone/uboot and other)
#
#  0x3360_0000                                  -
#    TA RAM: 12 MiB                             | TZDRAM
#  0x32a0_0000                                  -
#
#  CFG_WITH_PAGER=n                              -
#    TEE RAM: 4 MiB (TEE_RAM_VA_SIZE)           | TZDRAM
#  0x3260_0000 [TZDRAM_BASE, TEE_LOAD_ADDR]     -
#
#  CFG_WITH_PAGER=y
#    Unused
#  0x32607_0000                                 -
#    TEE RAM: 448 KiB (TZSRAM_SIZE)             | TZSRAM
#  0x3260_0000 [TZDRAM_BASE, TZSRAM_BASE, TEE_LOAD_ADDR]
#    OP-TEE Future Use: 2 MiB
#  0x3240_0000
#    Shared memory: 4 MB
#  0x3200_0000
#    Linux memory: 256MB
#  0x2200_0000
#    DSP reserved memory:      32MB
#  0x2000_0000 [DRAM_BASE]
#
CFG_TZDRAM_START ?= 0x32600000
CFG_TZDRAM_SIZE ?= 0x01000000
CFG_TEE_RAM_VA_SIZE ?= 0x00400000
CFG_SHMEM_START ?= 0x32000000
CFG_SHMEM_SIZE ?= 0x00400000
else
$(error Error: Not supported PLATFORM_FLAVOR or NULL PLATFORM_FLAVOR)
endif
