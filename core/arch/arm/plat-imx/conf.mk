PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6d-flavorlist =
mx6dl-flavorlist = mx6dlsabresd mx6dlsabreauto
mx6q-flavorlist = mx6qsabrelite mx6qsabresd mx6qsabreauto
mx6qp-flavorlist = mx6qpsabresd mx6qpsabreauto
mx6s-flavorlist =
mx6sl-flavorlist = mx6slevk
mx6sll-flavorlist = mx6sllevk
mx6sx-flavorlist = mx6sxsabresd mx6sxsabreauto
mx6ul-flavorlist = mx6ulevk mx6ul9x9evk
mx6ull-flavorlist = mx6ullevk
mx7-flavorlist = mx7dsabresd mx7swarp7

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6UL,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ull-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6ULL,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6Q,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6qp-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6QP,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6D,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 2
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6DL,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 2
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6S,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sx-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SX,y)
$(call force,CFG_IMX_UART,y)
CFG_IMX_CAAM ?= y
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SL,y)
$(call force,CFG_IMX_UART,y)
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sll-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SLL,y)
$(call force,CFG_IMX_UART,y)
CFG_TEE_CORE_NB_CORE ?= 1
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7-flavorlist)))
$(call force,CFG_MX7,y)
CFG_IMX_CAAM ?= y
#Note: This is not correct 7s is a single core
# but it should work as well
CFG_TEE_CORE_NB_CORE ?= 2
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

# Common i.MX6/7 Configs
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
CFG_TZC380 ?= y
CFG_CSU ?= y
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y

# i.MX6UL/ULL specific config
ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
include core/arch/arm/cpu/cortex-a7.mk
endif

# i.MX6 Solo/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
      $(CFG_MX6SX) $(CFG_MX6SL) $(CFG_MX6SLL)), y)
include core/arch/arm/cpu/cortex-a9.mk
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
CFG_SCU ?= y
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_ENABLE_SCTLR_RR ?= y
endif

# i.MX7 specific config
ifeq ($(filter y, $(CFG_MX7)), y)
include core/arch/arm/cpu/cortex-a7.mk
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_INIT_CNTVOFF ?= y
endif

# Add some default Config
ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ul9x9evk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ullevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabrelite))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
# Currently there is a board rework to enable TZASC on i.MX6QP
CFG_TZC380 = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
# Currently there is a board rework to enable TZASC on i.MX6QP
CFG_TZC380 = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6slevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x20000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sllevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DDR_SIZE ?= 0x20000000
CFG_PSCI_ARM32 ?= y
# TZASC config is not defined for the warp board
CFG_TZC380 = n
endif

ifeq ($(filter y, $(CFG_PSCI_ARM32)), y)
CFG_HWSUPP_MEM_PERM_WXN = n
CFG_IMX_WDOG ?= y
endif

CFG_MMAP_REGIONS ?= 24

ta-targets = ta_arm32
