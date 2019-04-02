PLATFORM_FLAVOR ?= ns3

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_8250_UART,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_TEE_CORE_DEBUG,n)
$(call force,CFG_GIC,y)

$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_TEE_CORE_NB_CORE,8)
CFG_TZDRAM_START ?= 0x8e000000
CFG_TZDRAM_SIZE ?= 0x01000000 # 16MB
CFG_SHMEM_START ?= ($(CFG_TZDRAM_START) - $(CFG_SHMEM_SIZE))
CFG_SHMEM_SIZE ?=  0x01000000 # 16MB
CFG_TEE_RAM_VA_SIZE := 0x400000 # 4MB

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

ifeq ($(PLATFORM_FLAVOR),ns3)
$(call force,CFG_PL022,y)
$(call force,CFG_BCM_HWRNG,y)
$(call force,CFG_BCM_SOTP,y)
endif

ifeq ($(DEBUG),1)
platform-cflags += -gdwarf-2
platform-aflags += -gdwarf-2
endif
