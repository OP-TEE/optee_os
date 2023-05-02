PLATFORM_FLAVOR ?= hikey

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

CFG_NUM_THREADS ?= 8
CFG_CRYPTO_WITH_CE ?= y

ifeq ($(PLATFORM_FLAVOR),hikey)
CFG_CORE_HEAP_SIZE ?= 73728
CFG_PL061 ?= y
CFG_PL022 ?= y
CFG_SPI ?= y

ifeq ($(CFG_SPI_TEST),y)
$(call force,CFG_SPI,y)
endif

ifeq ($(CFG_SPI),y)
$(call force,CFG_PL061,y)
$(call force,CFG_PL022,y)
endif

ifeq ($(CFG_PL061),y)
core-platform-cppflags		+= -DPLAT_PL061_MAX_GPIOS=160
endif
endif

CFG_CACHE_API ?= y
CFG_SECURE_DATA_PATH ?= n
CFG_TEE_SDP_MEM_BASE ?= 0x3E800000
CFG_TEE_SDP_MEM_SIZE ?= 0x00400000

ifeq ($(PLATFORM_FLAVOR),hikey)
CFG_CONSOLE_UART ?= 3
CFG_DRAM_SIZE_GB ?= 2
endif

ifeq ($(PLATFORM_FLAVOR),hikey960)
CFG_CONSOLE_UART ?= 6
CFG_DRAM_SIZE_GB ?= 3
CFG_CORE_BGET_BESTFIT ?= y
ifeq ($(CFG_ARM32_core),y)
CFG_ASAN_SHADOW_OFFSET ?= 0x372E38E0
endif
# Hikey960 4G/6G versions have physical addresses above 4G range
ifneq (,$(filter 4 6,$(CFG_DRAM_SIZE_GB)))
$(call force,CFG_CORE_ARM64_PA_BITS,36)
endif
endif

CFG_TZDRAM_START ?= 0x3F000000
CFG_TZDRAM_SIZE ?= 0x01000000
CFG_SHMEM_START ?= 0x3EE00000
CFG_SHMEM_SIZE ?= 0x00200000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000

CFG_IN_TREE_EARLY_TAS += avb/023f8f1a-292a-432b-8fc4-de8471358067

CFG_EMBED_DTB_SOURCE_FILE ?= hikey.dts
