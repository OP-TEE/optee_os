include core/arch/$(ARCH)/plat-$(PLATFORM)/$(PLATFORM_FLAVOR)/config.mk

CFG_MMAP_REGIONS ?= 13

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CRYPTO_WITH_CE,y)
endif

$(call force,CFG_SECSTOR_TA,n)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CACHE_API,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CORE_HEAP_SIZE,1048576) # 1MB

CFG_WITH_STATS ?= y

CFG_RPMB_FS ?= y
ifeq ($(CFG_RPMB_FS),y)
CFG_RPMB_WRITE_KEY ?= y
CFG_REE_FS_ALLOW_RESET ?= y
endif

ifeq ($(CFG_RPMB_FS),y)
CFG_IN_TREE_EARLY_TAS += avb/023f8f1a-292a-432b-8fc4-de8471358067
endif

