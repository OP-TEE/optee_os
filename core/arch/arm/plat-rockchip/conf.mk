PLATFORM_FLAVOR ?= rk322x

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_8250_UART,y)

CFG_DT ?= y
CFG_WITH_STATS ?= y
CFG_NUM_THREADS ?= 4

ifeq ($(PLATFORM_FLAVOR),rk322x)
include ./core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)

CFG_TZDRAM_START ?= 0x68400000
CFG_TZDRAM_SIZE ?= 0x00200000
CFG_SHMEM_START ?= 0x68600000
CFG_SHMEM_SIZE ?= 0x00100000

CFG_EARLY_CONSOLE ?= y
CFG_EARLY_CONSOLE_BASE ?= UART2_BASE
CFG_EARLY_CONSOLE_SIZE ?= UART2_SIZE
CFG_EARLY_CONSOLE_BAUDRATE ?= 1500000
CFG_EARLY_CONSOLE_CLK_IN_HZ ?= 24000000
endif

CFG_EARLY_CONSOLE ?= n

ifeq ($(PLATFORM_FLAVOR),rk3399)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,6)
$(call force,CFG_ARM_GICV3,y)

CFG_TZDRAM_START ?= 0x30000000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_SHMEM_START  ?= 0x32000000
CFG_SHMEM_SIZE   ?= 0x00400000
endif

ifeq ($(PLATFORM_FLAVOR),px30)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)

CFG_TZDRAM_START ?= 0x30000000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_SHMEM_START  ?= 0x32000000
CFG_SHMEM_SIZE   ?= 0x00400000
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_WITH_LPAE,y)
ta-targets = ta_arm64
endif
