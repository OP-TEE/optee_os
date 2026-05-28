# Qualcomm platform support

PLATFORM_FLAVOR ?= kodiak

$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_ARM64_PA_BITS,40)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_QCOM_GENI_UART,y)
$(call force,CFG_CRYPTO_WITH_CE,y)
$(call force,CFG_HW_UNIQUE_KEY_LENGTH,32)

# The GENI UART is shared with the Linux kernel and an excessively long
# wait period may lead to RCU stall warnings depending on system load.
# Make this value configurable per platform.
CFG_QCOM_GENI_UART_RDY_WAIT_USEC ?= 1000

ta-targets = ta_arm64
supported-ta-targets ?= ta_arm64

# Architecture family mapping
HOYA_ARCH_CHIPSETS := kodiak lemans

ifneq (,$(filter $(PLATFORM_FLAVOR),$(HOYA_ARCH_CHIPSETS)))
QCOM_ARCH_FAMILY := hoya
else
$(error Unsupported PLATFORM_FLAVOR: $(PLATFORM_FLAVOR))
endif

# Include arch/target specific configurations if present
-include core/arch/arm/plat-qcom/$(QCOM_ARCH_FAMILY)/qcom-arch.mk
-include core/arch/arm/plat-qcom/$(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)/target.mk
