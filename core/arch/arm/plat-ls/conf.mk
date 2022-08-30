PLATFORM_FLAVOR ?= ls1012ardb

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_16550_UART,y)
$(call force,CFG_LS,y)

$(call force,CFG_DRAM0_BASE,0x80000000)
$(call force,CFG_TEE_OS_DRAM0_SIZE,0x4000000)

ifeq ($(PLATFORM_FLAVOR),ls1012ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_DRAM0_SIZE,0x40000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_NUM_THREADS ?= 2
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1043ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1046ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1088ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
$(call force,CFG_ARM_GICV3,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls2088ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),lx2160aqds)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,16)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_DRAM1_BASE,0x2080000000)
$(call force,CFG_DRAM1_SIZE,0x1F80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_EMBED_DTB,y)
$(call force,CFG_EMBED_DTB_SOURCE_FILE,fsl-lx2160a-qds.dts)
CFG_LS_I2C ?= y
CFG_LS_GPIO ?= y
CFG_LS_DSPI ?= y
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),lx2160ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,16)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_DRAM1_BASE,0x2080000000)
$(call force,CFG_DRAM1_SIZE,0x1F80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_EMBED_DTB,y)
$(call force,CFG_EMBED_DTB_SOURCE_FILE,fsl-lx2160a-rdb.dts)
CFG_LS_I2C ?= y
CFG_LS_GPIO ?= y
CFG_LS_DSPI ?= y
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1028ardb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
CFG_TZDRAM_START ?= ((CFG_DRAM0_BASE + CFG_DRAM0_SIZE) - CFG_TEE_OS_DRAM0_SIZE)
CFG_TZDRAM_SIZE ?= ( CFG_TEE_OS_DRAM0_SIZE - CFG_SHMEM_SIZE)
#CFG_SHMEM_START (Non-Secure shared memory) needs to be 2MB aligned boundary for TZASC 380 configuration.
CFG_SHMEM_START ?= ((CFG_DRAM0_BASE + CFG_DRAM0_SIZE) - CFG_SHMEM_SIZE)
$(call force,CFG_ARM64_core,y)
CFG_USER_TA_TARGETS ?= ta_arm64
else
#In ARMv7 platform CFG_SHMEM_SIZE is different to that of ARMv8 platforms.
CFG_TZDRAM_START ?= ((CFG_DRAM0_BASE + CFG_DRAM0_SIZE) - CFG_TEE_OS_DRAM0_SIZE)
CFG_TZDRAM_SIZE ?= ( CFG_TEE_OS_DRAM0_SIZE - (2*CFG_SHMEM_SIZE))
#CFG_SHMEM_START (Non-Secure shared memory) needs to be 2MB aligned boundary for TZASC 380 configuration.
CFG_SHMEM_START ?= ((CFG_DRAM0_BASE + CFG_DRAM0_SIZE) - (2*CFG_SHMEM_SIZE))
endif

#Keeping Number of TEE thread equal to number of cores on the SoC
CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)

ifneq ($(CFG_ARM64_core),y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
endif

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n

# NXP CAAM support is not enabled by default and can be enabled
# on the command line
CFG_NXP_CAAM ?= n

ifeq ($(CFG_NXP_CAAM),y)
# If NXP CAAM Driver is supported, the Crypto Driver interfacing
# it with generic crypto API can be enabled.
CFG_CRYPTO_DRIVER ?= y
CFG_CRYPTO_DRIVER_DEBUG ?= 0
else
$(call force,CFG_CRYPTO_DRIVER,n)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
endif

# Cryptographic configuration
include core/arch/arm/plat-ls/crypto_conf.mk
