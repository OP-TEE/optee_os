ifeq ($(PLATFORM_FLAVOR),tcc805x)
CFG_PL011 ?= y
CFG_OPENEDGES_OMC ?= y
CFG_ARM_SMCCC_TRNG ?= y

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,35)
$(call force,CFG_TEE_CORE_NB_CORE,4)

CFG_TZDRAM_START ?= 0x2E000000
CFG_TZDRAM_SIZE ?= 0x02000000

include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_ARM64_core,y)

TCMKTOOL_IMGNAME ?= A72-OPTEE
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CACHE_API,y)
$(call force,CFG_CORE_RESERVED_SHM,n)

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CRYPTO_WITH_CE,y)
endif

CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)
CFG_SECSTOR_TA ?= n
CFG_CORE_HEAP_SIZE ?= 1048576
CFG_WITH_STATS ?= y

ifeq ($(CFG_RPMB_FS),y)
CFG_IN_TREE_EARLY_TAS += avb/023f8f1a-292a-432b-8fc4-de8471358067
endif
