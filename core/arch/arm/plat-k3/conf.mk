CFG_WITH_STATS ?= y
CFG_CRYPTO_WITH_CE ?= y
CFG_CONSOLE_UART ?= 0

# Disable console output after boot as the UART may
# become unavailable due to runtime power management
CFG_CONSOLE_RUNTIME_SET ?= y
CFG_CONSOLE_RUNTIME_LOG_LEVEL ?= 0

ifeq ($(PLATFORM_FLAVOR),am62lx)
CFG_TZDRAM_START ?= 0x80200000
CFG_TZDRAM_SIZE ?= 0x00400000 # 20MB

else
CFG_TZDRAM_START ?= 0x9e800000
CFG_TZDRAM_SIZE ?= 0x01400000 # 20MB

endif
CFG_WITH_SOFTWARE_PRNG ?= n
CFG_SHMEM_START ?= ($(CFG_TZDRAM_START) + $(CFG_TZDRAM_SIZE))
CFG_SHMEM_SIZE ?= 0x00400000 # 4MB

$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_8250_UART,y)
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_K3_OTP_KEYWRITING,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)

ifneq (,$(filter ${PLATFORM_FLAVOR},am65x))
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
endif

ifneq ($(CFG_WITH_SOFTWARE_PRNG),y)
$(call force,CFG_EIP76D_TRNG,y)
ifeq ($(PLATFORM_FLAVOR),am62lx)
$(call force,CFG_DTHEV2,y)
else
$(call force,CFG_SA2UL,y)
endif
CFG_HWRNG_QUALITY ?= 1024
CFG_HWRNG_PTA ?= y
endif

include core/arch/arm/cpu/cortex-armv8-0.mk
