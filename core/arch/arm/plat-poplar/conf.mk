include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)

$(call force,CFG_PL011,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
CFG_CORE_TZSRAM_EMUL_SIZE ?= 655360
else
$(call force,CFG_ARM32_core,y)
CFG_CORE_TZSRAM_EMUL_SIZE ?= 524288
endif

CFG_NUM_THREADS ?= 4
CFG_CRYPTO_WITH_CE ?= y
# Overrides default in mk/config.mk with 96 kB
CFG_CORE_HEAP_SIZE ?= 98304

CFG_PL061 ?= y

ifeq ($(CFG_PL061),y)
core-platform-cppflags		+= -DPLAT_PL061_MAX_GPIOS=104
endif

CFG_TEE_SDP_MEM_BASE ?= 0x02800000
CFG_TEE_SDP_MEM_SIZE ?= 0x00400000

CFG_DRAM_SIZE_GB ?= 2
