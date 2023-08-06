PLATFORM_FLAVOR ?= npcm845x

ifeq ($(PLATFORM_FLAVOR),npcm845x)
include core/arch/arm/cpu/cortex-armv8-0.mk
CFG_ARM64_core ?= y
endif #npcm845x

CFG_USER_TA_TARGETS ?= ta_arm64

$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV2,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_16550_UART,y)

# Not used now for current platform
$(call force,CFG_EXTERNAL_DT,n)

CFG_WITH_STATS ?= y

# To enable version printing with color in main
CFG_NPCM_DEBUG ?= n

ifeq ($(PLATFORM_FLAVOR),npcm845x)
CFG_TEE_CORE_NB_CORE ?= 4
# [3000.0000 031f.ffff] is reserved to early boot
CFG_TZDRAM_START ?= 0x02100000
CFG_TZDRAM_SIZE  ?= 0x03f00000
# SHM chosen arbitrary, in a way that it does not interfere
# with initial location of linux kernel, dtb and initrd.
CFG_SHMEM_START ?= 0x06000000
CFG_SHMEM_SIZE  ?= 0x00200000
# When Secure Data Path is enable, last MByte of TZDRAM is SDP test memory.
CFG_TEE_SDP_MEM_BASE ?= 0x05F00000
CFG_TEE_SDP_MEM_SIZE ?= 0x00100000
$(call force,CFG_DT,y)
CFG_DTB_MAX_SIZE ?= 0x100000
$(call force,CFG_WITH_PAGER,n,Pager is not supported for NPCM845x)
else
$(error Unsupported platform flavor "$(PLATFORM_FLAVOR)")
endif #npcm845x
