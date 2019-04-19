PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6ul-flavorlist = \
	mx6ulevk \
	mx6ulccimx6ulsbcpro \

mx6ull-flavorlist = \
	mx6ullevk \

mx6q-flavorlist = \
	mx6qsabrelite \
	mx6qsabresd \
	mx6qhmbedge \

mx6sx-flavorlist = \
	mx6sxsabreauto \
	mx6sxudooneofull \

mx6d-flavorlist = \
	mx6dhmbedge \

mx6dl-flavorlist = \
	mx6dlsabresd \
	mx6dlhmbedge \

mx6s-flavorlist = \
	mx6shmbedge \

mx7-flavorlist = \
	mx7dsabresd \
	mx7dpico_mbl \
	mx7swarp7 \
	mx7swarp7_mbl \
	mx7dclsom \

imx8mq-flavorlist = \
	imx8mqevk

imx8mm-flavorlist = \
	imx8mmevk

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6UL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ull-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6ULL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_NXP_CAAM,n)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6Q,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6D,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6DL,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6S,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_NXP_CAAM,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sx-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SX,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7-flavorlist)))
$(call force,CFG_MX7,y)
CFG_TEE_CORE_NB_CORE ?= 2
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(imx8mq-flavorlist)))
$(call force,CFG_IMX8MQ,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(imx8mm-flavorlist)))
$(call force,CFG_IMX8MM,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dsabresd))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
$(call force,CFG_TEE_CORE_NB_CORE,2)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dclsom))
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dpico_mbl))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x87800000
CFG_DT_ADDR ?= 0x83100000
CFG_UART_BASE ?= UART5_BASE
CFG_BOOT_SECONDARY_REQUEST ?= n
CFG_EXTERNAL_DTB_OVERLAY ?= y
CFG_IMX_WDOG_EXT_RESET ?= y
$(call force,CFG_TEE_CORE_NB_CORE,2)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_BOOT_SECONDARY_REQUEST ?= n
$(call force,CFG_TEE_CORE_NB_CORE,1)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7_mbl))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x87800000
CFG_DT_ADDR ?= 0x83100000
CFG_BOOT_SECONDARY_REQUEST ?= n
CFG_EXTERNAL_DTB_OVERLAY = y
CFG_IMX_WDOG_EXT_RESET = y
$(call force,CFG_TEE_CORE_NB_CORE,1)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabresd mx6dlsabresd \
	mx6dlsabrelite mx6dhmbedge mx6dlhmbedge))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x12000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qhmbedge))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6shmbedge))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x12000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabrelite mx6dlsabrelite))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_UART_BASE ?= UART2_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabreauto))
CFG_DDR_SIZE ?= 0x80000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifeq ($(PLATFORM_FLAVOR), mx6sxudooneofull)
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulevk mx6ullevk))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulccimx6ulsbcpro))
CFG_DDR_SIZE ?= 0x10000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_UART_BASE ?= UART5_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),imx8mqevk))
CFG_DDR_SIZE ?= 0xc0000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),imx8mmevk))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART2_BASE
endif

# i.MX6 Solo/SoloX/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
      $(CFG_MX6SX)), y)
include core/arch/arm/cpu/cortex-a9.mk

$(call force,CFG_PL310,y)

CFG_PL310_LOCKED ?= y
CFG_ENABLE_SCTLR_RR ?= y
endif

ifeq ($(filter y, $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S)), y)
CFG_DRAM_BASE ?= 0x10000000
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL) $(CFG_MX6SX)))
CFG_DRAM_BASE ?= 0x80000000
endif

ifeq ($(filter y, $(CFG_MX7)), y)
CFG_INIT_CNTVOFF ?= y
CFG_DRAM_BASE ?= 0x80000000
endif

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7)))
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_PM_STUBS,y)

CFG_BOOT_SYNC_CPU ?= n
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_DT ?= y
CFG_PAGEABLE_ADDR ?= 0
CFG_PSCI_ARM32 ?= y
CFG_SECURE_TIME_SOURCE_REE ?= y
CFG_UART_BASE ?= UART1_BASE
endif

ifeq ($(filter y, $(CFG_PSCI_ARM32)), y)
CFG_HWSUPP_MEM_PERM_WXN = n
CFG_IMX_WDOG ?= y
endif

ifeq ($(CFG_ARM64_core),y)
# arm-v8 platforms
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

CFG_CRYPTO_WITH_CE ?= y
CFG_PM_STUBS ?= y

supported-ta-targets = ta_arm64
endif

CFG_TZDRAM_START ?= ($(CFG_DRAM_BASE) - 0x02000000 + $(CFG_DDR_SIZE))
CFG_TZDRAM_SIZE ?= 0x01e00000
CFG_SHMEM_START ?= ($(CFG_TZDRAM_START) + $(CFG_TZDRAM_SIZE))
CFG_SHMEM_SIZE ?= 0x00200000

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
CFG_MMAP_REGIONS ?= 24

# Almost all platforms include CAAM HW Modules, except the
# one force to be disabled
CFG_NXP_CAAM ?= y

ifeq ($(CFG_NXP_CAAM),y)
# If NXP CAAM Driver is supported, the Crypto Driver interfacing
# it with generic crypto API can be enabled.
CFG_CRYPTO_DRIVER ?= y
# Crypto Driver Debug
CFG_CRYPTO_DRV_DBG ?= n
else
$(call force,CFG_CRYPTO_DRIVER,n)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
endif

# Cryptographic configuration
include core/arch/arm/plat-imx/crypto_conf.mk
