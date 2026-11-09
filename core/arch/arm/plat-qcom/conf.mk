# Qualcomm platform support

PLATFORM_FLAVOR ?= kodiak

# The default value CFG_INSECURE ?= y is assigned in mk/config.mk.
# But mk/config.mk is included after $(platform-dir)/conf.mk from
# core/core.mk.
# Since we are making decision based on CFG_INSECURE for enabling
# certain platform features, we need to set it early here also.
CFG_INSECURE ?= y

$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_ARM64_PA_BITS,40)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CRYPTO_WITH_CE,y)
$(call force,CFG_HW_UNIQUE_KEY_LENGTH,32)

CFG_QCOM_GENI_UART ?= y

# The GENI UART is shared with the Linux kernel and an excessively long
# wait period may lead to RCU stall warnings depending on system load.
# Make this value configurable per platform.
CFG_QCOM_GENI_UART_RDY_WAIT_USEC ?= 1000

# PIL PAS authentication metadata slots, defaults to 1.
# Platform-specific configs may override this value.
CFG_PAS_MD_SLOTS ?= 1

ta-targets = ta_arm64
supported-ta-targets ?= ta_arm64

# Architecture family mapping
HOYA_ARCH_CHIPSETS := kodiak lemans monaco
BOBCAT_ARCH_CHIPSETS := ipq96xx ipq52xx
WILDCAT_ARCH_CHIPSETS := nord cacao
BRUIN_ARCH_CHIPSETS := shikra agatti

ifneq (,$(filter $(PLATFORM_FLAVOR),$(HOYA_ARCH_CHIPSETS)))
QCOM_ARCH_FAMILY := hoya
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(BOBCAT_ARCH_CHIPSETS)))
QCOM_ARCH_FAMILY := bobcat
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(WILDCAT_ARCH_CHIPSETS)))
QCOM_ARCH_FAMILY := wildcat
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(BRUIN_ARCH_CHIPSETS)))
QCOM_ARCH_FAMILY := bruin
else
$(error Unsupported PLATFORM_FLAVOR: $(PLATFORM_FLAVOR))
endif

# Include arch/target specific configurations if present
-include core/arch/arm/plat-qcom/$(QCOM_ARCH_FAMILY)/qcom-arch.mk
-include core/arch/arm/plat-qcom/$(QCOM_ARCH_FAMILY)/$(PLATFORM_FLAVOR)/target.mk

# Format of the fuse provisioning data: n for the segmented rev 2 format, y
# for the flat rev 3 format (see CFG_QCOM_QFPROM_FUSEPROV).
CFG_QCOM_PROVISION_SEC_ELF_V3 ?= n

# Fuse access used by the provisioning: qfprom for the memory mapped fuse
# controller, tme for the security processor. The tme backend supports the
# flat rev 3 format only.
CFG_QCOM_PROVISION_BACKEND ?= qfprom
ifeq ($(CFG_QCOM_PROVISION_BACKEND),tme)
CFG_QCOM_PROVISION_BACKEND_TME := y
$(call force,CFG_QCOM_TME_INTF,y)
$(call force,CFG_QCOM_QFPROM_FEC_LIB,y)
ifneq ($(CFG_QCOM_PROVISION_SEC_ELF_V3),y)
$(error CFG_QCOM_PROVISION_BACKEND=tme needs CFG_QCOM_PROVISION_SEC_ELF_V3=y)
endif
else ifeq ($(CFG_QCOM_PROVISION_BACKEND),qfprom)
CFG_QCOM_PROVISION_BACKEND_TME := n
ifeq ($(CFG_QCOM_PROVISION_SEC_ELF_V3),y)
$(error CFG_QCOM_PROVISION_SEC_ELF_V3=y needs CFG_QCOM_PROVISION_BACKEND=tme)
endif
else
$(error Unsupported CFG_QCOM_PROVISION_BACKEND: $(CFG_QCOM_PROVISION_BACKEND))
endif

# When enabled, CFG_QCOM_TME_INTF embeds the TME interface: the
# functions that can communicate with TME. The messages are sent to TME
# through TF-A, so it needs CFG_QCOM_TFA_COMM.
CFG_QCOM_TME_INTF ?= n
ifeq ($(CFG_QCOM_TME_INTF),y)
$(call force,CFG_QCBOR,y)
$(call force,CFG_QCOM_TFA_COMM,y)
endif

# Commit the anti-rollback state through the security processor before the
# fuses are programmed. This is irreversible, and the security processor
# expects it once the boot is declared good, so it stays off until that
# timing is confirmed for the target.
CFG_QCOM_TME_ARB ?= n
ifeq ($(CFG_QCOM_TME_ARB)-$(CFG_QCOM_PROVISION_BACKEND_TME),y-n)
$(error CFG_QCOM_TME_ARB=y needs CFG_QCOM_PROVISION_BACKEND=tme)
endif

# The flat rev 3 format carries no hash or signature. It must only be enabled
# when the memory holding it is secure and was authenticated before OP-TEE
# starts.
CFG_QCOM_PROVISION_BUFFER_AUTHENTICATED ?= n
ifeq ($(CFG_QCOM_PROVISION_SEC_ELF_V3)-$(CFG_QCOM_PROVISION_BUFFER_AUTHENTICATED),y-n)
$(error CFG_QCOM_PROVISION_SEC_ELF_V3=y needs CFG_QCOM_PROVISION_BUFFER_AUTHENTICATED=y)
endif
