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

ifeq ($(PLATFORM_FLAVOR),otx2t96)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,24)
$(call force,CFG_CLUSTERS_PER_NODE,4)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x01000000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_HW_UNQ_KEY_SUPPORT ?= y
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),otx2f95)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,6)
$(call force,CFG_CLUSTERS_PER_NODE,1)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x01000000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_HW_UNQ_KEY_SUPPORT ?= y
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),otx2t98)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,36)
$(call force,CFG_CLUSTERS_PER_NODE,6)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x01000000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
#$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_HW_UNQ_KEY_SUPPORT ?= y
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),cn10ka)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,24)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x03400000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),cn10kb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x03400000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),cnf10ka)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,18)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x03400000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(PLATFORM_FLAVOR),cnf10kb)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,12)
$(call force,CFG_TZDRAM_START,0x00001000)
$(call force,CFG_TZDRAM_SIZE,0x000a00000)
$(call force,CFG_SHMEM_START,0x03400000)
$(call force,CFG_SHMEM_SIZE,0x00800000)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,48)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
$(call force,CFG_PL011,y)
$(call force,CFG_ARM_GICV3,y)
CFG_USER_TA_TARGETS ?= ta_arm64
CFG_NUM_THREADS ?= CFG_TEE_CORE_NB_CORE
CFG_CORE_HEAP_SIZE ?= 131072
endif

ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)

CFG_WITH_STATS ?= y
