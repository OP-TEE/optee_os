PLATFORM_FLAVOR ?= ns3

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_8250_UART,y)
$(call force,CFG_TEE_CORE_DEBUG,n)
$(call force,CFG_GIC,y)

$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
CFG_TZDRAM_START ?= 0x8e000000
CFG_TZDRAM_SIZE ?= 0x01000000 # 16MB
CFG_SHMEM_START ?= ($(CFG_TZDRAM_START) - $(CFG_SHMEM_SIZE))
CFG_SHMEM_SIZE ?=  0x01000000 # 16MB
CFG_TEE_RAM_VA_SIZE := 0x400000 # 4MB

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

ifeq ($(PLATFORM_FLAVOR),ns3)
$(call force,CFG_PL022,y)
$(call force,CFG_SP805_WDT,y)
$(call force,CFG_BCM_HWRNG,y)
$(call force,CFG_BCM_SOTP,y)
$(call force,CFG_BCM_GPIO,y)
CFG_BNXT_FW ?= y
CFG_BCM_ELOG_DUMP ?= y
endif

CFG_BCM_ELOG_AP_UART_LOG_BASE ?= 0x8f110000
CFG_BCM_ELOG_AP_UART_LOG_SIZE ?= 0x10000

CFG_BCM_ELOG_BASE ?= 0x8f120000
CFG_BCM_ELOG_SIZE ?= 0x100000

ifeq ($(DEBUG),1)
platform-cflags += -gdwarf-2
platform-aflags += -gdwarf-2
endif

CFG_WITH_STACK_CANARIES ?= n
