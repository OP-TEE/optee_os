ta-targets = ta_arm64

ifeq ($(CFG_ARM64_core),y)
CFG_WITH_LPAE := y
ifeq ($(CROSS_COMPILE_user_ta),)
ARM64_user_build := y
endif
else
CFG_ARM32_core ?= y
CFG_MMU_V7_TTB ?= y
endif

CFG_WITH_ARM_TRUSTED_FW := y

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y
CFG_SECURE_TIME_SOURCE_CNTPCT := y
CFG_GIC := y
CFG_HWSUPP_MEM_PERM_PXN := y
CFG_WITH_STACK_CANARIES := y
CFG_PM_STUBS := y
CFG_GENERIC_BOOT := y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_TEE_FS_KEY_MANAGER_TEST := y

CFG_OTP_SUPPORT := n

CFG_DYNAMIC_TA_AUTH_BY_HWENGINE ?= n
ifeq ($(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE),y)
core-platform-cppflags += -DRCAR_DYNAMIC_TA_AUTH_BY_HWENGINE
endif

core-platform-cppflags += -DPLATFORM_RCAR
core-platform-cppflags += -DPLATFORM_DEFINE_TEE_MMU_KMAP

# Not covered by compile - /core/arch/arm/kernel/trace_ext.c
WITH_TRACE_EXT := n

# Compiler switch - Debug log(Linux terminal log)
RCAR_DEBUG_LOG ?= 0
ifneq ($(RCAR_DEBUG_LOG),0)
core-platform-cppflags += -DRCAR_DEBUG_LOG
endif

RCAR_INTCTX_LOG ?= 0
ifneq ($(RCAR_INTCTX_LOG),0)
core-platform-cppflags += -DRCAR_INTCTX_LOG
endif

