include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)

$(call force,CFG_8250_UART,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
endif

CFG_NUM_THREADS ?= 4
CFG_CRYPTO_WITH_CE ?= n
CFG_WITH_STACK_CANARIES ?= y

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_WITH_STATS ?= y

arm32-platform-cflags += -Wno-error=cast-align
arm64-platform-cflags += -Wno-error=cast-align

$(call force,CFG_CRYPTO_SHA256_ARM32_CE,n)
$(call force,CFG_CRYPTO_SHA256_ARM64_CE,n)
$(call force,CFG_CRYPTO_SHA1_ARM32_CE,n)
$(call force,CFG_CRYPTO_SHA1_ARM64_CE,n)
$(call force,CFG_CRYPTO_AES_ARM64_CE,n)
