PLATFORM_FLAVOR ?= npcm845x

ifeq ($(PLATFORM_FLAVOR),npcm845x)
include core/arch/arm/cpu/cortex-armv8-0.mk
CFG_ARM64_core = y
endif #npcm845x
CFG_USER_TA_TARGETS ?= ta_arm64
DEBUG ?= 1

ifeq ($(platform-debugger-arm),1)
# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2
endif

ifeq ($(platform-flavor-armv8),1)
CFG_WITH_ARM_TRUSTED_FW = y
endif

CFG_GIC = y
CFG_ARM_GICV2 = y
CFG_SECURE_TIME_SOURCE_CNTPCT = y
CFG_16550_UART = y

ifeq ($(CFG_CORE_TPM_EVENT_LOG),y)
# NOTE: Below values for the TPM event log are implementation
# dependent and used mostly for debugging purposes.
# Care must be taken to properly configure them if used.
#CFG_TPM_LOG_BASE_ADDR ?= 0x402c951
#CFG_TPM_MAX_LOG_SIZE ?= 0x200
endif

ifeq ($(CFG_ARM64_core),y)
CFG_WITH_LPAE = y
else
CFG_ARM32_core = y
endif

CFG_WITH_STATS ?= y
CFG_EXTERNAL_DT = n
CFG_WARN_INSECURE = n

ifeq ($(PLATFORM_FLAVOR),npcm845x)
CFG_TEE_CORE_NB_CORE = 4
# [3000.0000 031f.ffff] is reserved to early boot
CFG_TZDRAM_START ?= 0x00100000
CFG_TZDRAM_SIZE  ?= 0x00f00000
# SHM chosen arbitrary, in a way that it does not interfere
# with initial location of linux kernel, dtb and initrd.
CFG_SHMEM_START ?= 0x2FD00000 #0x42000000   # Hila to check 
CFG_SHMEM_SIZE  ?= 0x00200000
# When Secure Data Path is enable, last MByte of TZDRAM is SDP test memory.
CFG_TEE_SDP_MEM_SIZE ?= 0x00400000
$(call force,CFG_DT,y)
CFG_DTB_MAX_SIZE ?= 0x100000
endif
