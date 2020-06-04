PLATFORM_FLAVOR ?= armada7k8k

ifeq ($(PLATFORM_FLAVOR),armada7k8k)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_TZDRAM_START,0x04400000)
$(call force,CFG_TZDRAM_SIZE,0x00C00000)
$(call force,CFG_SHMEM_START,0x05000000)
$(call force,CFG_SHMEM_SIZE,0x00400000)
$(call force,CFG_TEE_RAM_VA_SIZE,0x00400000)
# If Secure Data Path is enabled, uses the TZDRAM last 4MByte
$(call force,CFG_TEE_SDP_MEM_SIZE,0x00400000)
platform-debugger-arm := 1
$(call force,CFG_8250_UART,y)
endif

ifeq ($(PLATFORM_FLAVOR),armada3700)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_TZDRAM_START,0x04400000)
$(call force,CFG_TZDRAM_SIZE,0x00C00000)
$(call force,CFG_SHMEM_START,0x05000000)
$(call force,CFG_SHMEM_SIZE,0x00400000)
$(call force,CFG_TEE_RAM_VA_SIZE,0x00400000)
# If Secure Data Path is enabled, uses the TZDRAM last 4MByte
$(call force,CFG_TEE_SDP_MEM_SIZE,0x00400000)
platform-debugger-arm := 1
$(call force,CFG_MVEBU_UART,y)
$(call force,CFG_ARM_GICV3,y)
endif

ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_GIC,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
endif

CFG_WITH_STATS ?= y
