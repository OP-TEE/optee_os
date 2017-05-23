PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6ul-flavorlist = mx6ulevk
mx6q-flavorlist = mx6qsabrelite mx6qsabresd
mx6d-flavorlist =
mx6dl-flavorlist = mx6dlsabresd
mx6s-flavorlist =

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6UL,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6Q,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6D,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6DL,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6S,y)
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif


# Common i.MX6 config
core_arm32-platform-aflags	+= -mfpu=neon

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y


# i.MX6UL specific config
ifeq ($(CFG_MX6UL),y)
include core/arch/arm/cpu/cortex-a7.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
endif


# i.MX6 Solo/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S)), y)
include core/arch/arm/cpu/cortex-a9.mk

$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
endif


ta-targets = ta_arm32

