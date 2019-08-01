PLATFORM_FLAVOR ?= ls1021atwr

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_16550_UART,y)
$(call force,CFG_PM_STUBS,y)

$(call force,CFG_DRAM0_BASE,0x80000000)
$(call force,CFG_TEE_OS_DRAM0_SIZE,0x4000000)

ifeq ($(PLATFORM_FLAVOR),ls1021atwr)
include core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_DRAM0_SIZE,0x40000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00100000
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif

ifeq ($(PLATFORM_FLAVOR),ls1021aqds)
include core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00100000
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif

ifeq ($(PLATFORM_FLAVOR),ls1012ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_DRAM0_SIZE,0x40000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1012afrwy)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_DRAM0_SIZE ?= 0x20000000
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1043ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1046ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1088ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
$(call force,CFG_ARM_GICV3,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls2088ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),lx2160ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,16)
$(call force,CFG_DRAM0_SIZE,0x80000000)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
CFG_SHMEM_SIZE ?= 0x00200000
endif

ifeq ($(PLATFORM_FLAVOR),ls1028ardb)
CFG_HW_UNQ_KEY_REQUEST ?= y
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
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
$(call force,CFG_SECONDARY_INIT_CNTFRQ,y)
endif

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
