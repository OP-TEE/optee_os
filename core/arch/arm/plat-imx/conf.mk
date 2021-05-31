PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6ul-flavorlist = \
	mx6ulevk \
	mx6ul9x9evk \
	mx6ulccimx6ulsbcpro \
	mx6ulccbv2 \

mx6ull-flavorlist = \
	mx6ullevk \
	mx6ulzevk \

mx6q-flavorlist = \
	mx6qsabrelite \
	mx6qsabreauto \
	mx6qsabresd \
	mx6qhmbedge \
	mx6qapalis \

mx6qp-flavorlist = \
	mx6qpsabreauto \
	mx6qpsabresd \

mx6sl-flavorlist = \
	mx6slevk

mx6sll-flavorlist = \
	mx6sllevk

mx6sx-flavorlist = \
	mx6sxsabreauto \
	mx6sxsabresd \
	mx6sxudooneofull \

mx6d-flavorlist = \
	mx6dhmbedge \
	mx6dapalis \

mx6dl-flavorlist = \
	mx6dlsabreauto \
	mx6dlsabresd \
	mx6dlhmbedge \

mx6s-flavorlist = \
	mx6shmbedge \
	mx6solosabresd \
	mx6solosabreauto \

mx7d-flavorlist = \
	mx7dsabresd \
	mx7dpico_mbl \
	mx7dclsom \

mx7s-flavorlist = \
	mx7swarp7 \
	mx7swarp7_mbl \

mx7ulp-flavorlist = \
	mx7ulpevk

mx8mq-flavorlist = \
	mx8mqevk

mx8mm-flavorlist = \
	mx8mmevk \
	mx8mm_cl_iot_gate

mx8mn-flavorlist = \
	mx8mnevk

mx8mp-flavorlist = \
	mx8mpevk \
	mx8mp_rsb3720_6g

mx8qm-flavorlist = \
	mx8qmmek \

mx8qx-flavorlist = \
	mx8qxpmek \

mx8dxl-flavorlist = \
	mx8dxlevk \

mx8ulp-flavorlist = \
	mx8ulpevk \

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6UL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_TZC380,y)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ull-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6ULL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_TZC380,y)
$(call force,CFG_IMX_CAAM,n)
$(call force,CFG_NXP_CAAM,n)
$(call force,CFG_IMX_DCP,y)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6Q,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_TZC380,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6qp-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6QP,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6D,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_TZC380,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6DL,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_TZC380,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6S,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_IMX_CAAM,n)
$(call force,CFG_NXP_CAAM,n)
$(call force,CFG_IMX_DCP,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sll-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SLL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_IMX_CAAM,n)
$(call force,CFG_NXP_CAAM,n)
$(call force,CFG_IMX_DCP,y)
$(call force,CFG_NO_SMP,y)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sx-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SX,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7s-flavorlist)))
$(call force,CFG_MX7,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7d-flavorlist)))
$(call force,CFG_MX7,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7ulp-flavorlist)))
$(call force,CFG_MX7ULP,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_TZC380,n)
$(call force,CFG_CSU,n)
$(call force,CFG_NXP_CAAM,n)
include core/arch/arm/cpu/cortex-a7.mk
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mq-flavorlist)))
$(call force,CFG_MX8MQ,y)
$(call force,CFG_MX8M,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mm-flavorlist)))
$(call force,CFG_MX8MM,y)
$(call force,CFG_MX8M,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mn-flavorlist)))
$(call force,CFG_MX8MN,y)
$(call force,CFG_MX8M,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mp-flavorlist)))
$(call force,CFG_MX8MP,y)
$(call force,CFG_MX8M,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_UART ?= y
CFG_DRAM_BASE ?= 0x40000000
CFG_TEE_CORE_NB_CORE ?= 4
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8qm-flavorlist)))
$(call force,CFG_MX8QM,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_IMX_SNVS,n)
CFG_IMX_LPUART ?= y
CFG_DRAM_BASE ?= 0x80000000
CFG_TEE_CORE_NB_CORE ?= 6
$(call force,CFG_IMX_OCOTP,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8qx-flavorlist)))
$(call force,CFG_MX8QX,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_IMX_SNVS,n)
CFG_IMX_LPUART ?= y
CFG_DRAM_BASE ?= 0x80000000
CFG_TEE_CORE_NB_CORE ?= 4
$(call force,CFG_IMX_OCOTP,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8dxl-flavorlist)))
$(call force,CFG_MX8DXL,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_IMX_SNVS,n)
CFG_IMX_LPUART ?= y
CFG_DRAM_BASE ?= 0x80000000
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_IMX_OCOTP,n)
$(call force,CFG_NXP_CAAM,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8ulp-flavorlist)))
$(call force,CFG_MX8ULP,y)
$(call force,CFG_ARM64_core,y)
CFG_IMX_LPUART ?= y
CFG_DRAM_BASE ?= 0x80000000
CFG_TEE_CORE_NB_CORE ?= 2
$(call force,CFG_NXP_SNVS,n)
$(call force,CFG_IMX_OCOTP,n)
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dsabresd))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_IMX_WDOG_EXT_RESET ?= y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dclsom))
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART1_BASE
CFG_IMX_WDOG_EXT_RESET ?= y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dpico_mbl))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x87800000
CFG_DT_ADDR ?= 0x83100000
CFG_UART_BASE ?= UART5_BASE
CFG_BOOT_SECONDARY_REQUEST ?= n
CFG_EXTERNAL_DTB_OVERLAY ?= y
CFG_IMX_WDOG_EXT_RESET ?= y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_BOOT_SECONDARY_REQUEST ?= n
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7_mbl))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x87800000
CFG_DT_ADDR ?= 0x83100000
CFG_BOOT_SECONDARY_REQUEST ?= n
CFG_EXTERNAL_DTB_OVERLAY = y
CFG_IMX_WDOG_EXT_RESET = y
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7ulpevk))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x60800000
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabresd mx6qsabresd mx6dlsabresd \
	mx6dlsabrelite mx6dhmbedge mx6dlhmbedge mx6solosabresd \
	mx6dapalis mx6qapalis))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x12000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabreauto mx6qsabreauto \
	mx6dlsabreauto mx6solosabreauto))
CFG_DDR_SIZE ?= 0x80000000
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_UART_BASE ?= UART4_BASE
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

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6slevk))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sllevk))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DDR_SIZE ?= 0x80000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabreauto))
CFG_DDR_SIZE ?= 0x80000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabresd))
CFG_DDR_SIZE ?= 0x40000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifeq ($(PLATFORM_FLAVOR), mx6sxudooneofull)
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulevk mx6ullevk mx6ulzevk))
CFG_DDR_SIZE ?= 0x20000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulccimx6ulsbcpro))
CFG_DDR_SIZE ?= 0x10000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_UART_BASE ?= UART5_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ul9x9evk))
CFG_DDR_SIZE ?= 0x10000000
CFG_NS_ENTRY_ADDR ?= 0x80800000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulccbv2))
CFG_DDR_SIZE ?= 0x10000000
CFG_UART_BASE ?= UART7_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mqevk))
CFG_DDR_SIZE ?= 0xc0000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mmevk))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART2_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mm_cl_iot_gate))
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART3_BASE
CFG_NSEC_DDR_1_BASE ?= 0x80000000UL
CFG_NSEC_DDR_1_SIZE ?= 0x40000000UL
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mnevk))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART2_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mpevk))
CFG_DDR_SIZE ?= UL(0x180000000)
CFG_UART_BASE ?= UART2_BASE
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mp_rsb3720_6g))
CFG_DDR_SIZE ?= UL(0x180000000)
CFG_UART_BASE ?= UART3_BASE
CFG_TZDRAM_START ?= 0x56000000
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8qxpmek mx8qmmek))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART0_BASE
CFG_NSEC_DDR_1_BASE ?= 0x880000000UL
CFG_NSEC_DDR_1_SIZE  ?= 0x380000000UL
CFG_CORE_ARM64_PA_BITS ?= 40
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8dxlevk))
CFG_DDR_SIZE ?= 0x40000000
CFG_UART_BASE ?= UART0_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8ulpevk))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART5_BASE
endif

# i.MX6 Solo/SL/SoloX/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
	$(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)), y)
include core/arch/arm/cpu/cortex-a9.mk

$(call force,CFG_PL310,y)

CFG_PL310_LOCKED ?= y
CFG_ENABLE_SCTLR_RR ?= y
CFG_SCU ?= y
endif

ifeq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S)), y)
CFG_DRAM_BASE ?= 0x10000000
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL) $(CFG_MX6SL) $(CFG_MX6SLL) \
	$(CFG_MX6SX)))
CFG_DRAM_BASE ?= 0x80000000
endif

ifeq ($(filter y, $(CFG_MX7)), y)
CFG_INIT_CNTVOFF ?= y
CFG_DRAM_BASE ?= 0x80000000
endif

ifeq ($(filter y, $(CFG_MX7ULP)), y)
CFG_INIT_CNTVOFF ?= y
CFG_DRAM_BASE ?= UL(0x60000000)
$(call force,CFG_IMX_LPUART,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,n)
endif

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7) $(CFG_MX7ULP)))
$(call force,CFG_GIC,y)

CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_DT ?= y
CFG_DTB_MAX_SIZE ?= 0x20000
CFG_PAGEABLE_ADDR ?= 0
CFG_PSCI_ARM32 ?= y
CFG_SECURE_TIME_SOURCE_REE ?= y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7) $(CFG_MX8MM)))
$(call force,CFG_IMX_UART,y)
ifeq ($(CFG_RPMB_FS),y)
CFG_IMX_SNVS ?= y
endif
endif

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7)))
CFG_CSU ?= y
endif

ifeq ($(filter y, $(CFG_PSCI_ARM32)), y)
CFG_HWSUPP_MEM_PERM_WXN = n
CFG_IMX_WDOG ?= y
endif

ifeq ($(CFG_ARM64_core),y)
# arm-v8 platforms
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GIC,y)
$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

CFG_CRYPTO_WITH_CE ?= y

supported-ta-targets = ta_arm64
endif

CFG_TZDRAM_START ?= ($(CFG_DRAM_BASE) - 0x02000000 + $(CFG_DDR_SIZE))
CFG_TZDRAM_SIZE ?= 0x01e00000
CFG_SHMEM_START ?= ($(CFG_TZDRAM_START) + $(CFG_TZDRAM_SIZE))
CFG_SHMEM_SIZE ?= 0x00200000

CFG_NSEC_DDR_0_BASE ?= $(CFG_DRAM_BASE)
CFG_NSEC_DDR_0_SIZE ?= ($(CFG_DDR_SIZE) - 0x02000000)

CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_MMAP_REGIONS ?= 24

# SE05X and OCOTP both implement tee_otp_get_die_id()
ifeq ($(CFG_NXP_SE05X),y)
$(call force,CFG_IMX_OCOTP,n)
endif
CFG_IMX_OCOTP ?= y

# Almost all platforms include CAAM HW Modules, except the
# ones forced to be disabled
CFG_NXP_CAAM ?= n

ifeq ($(CFG_NXP_CAAM),y)
ifeq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX) $(CFG_MX8DXL)), y)
CFG_IMX_SC ?= y
endif

# As NXP CAAM Driver is enabled, disable the small local CAAM driver
# used just to release Job Rings to Non-Secure world
$(call force,CFG_IMX_CAAM,n)
else

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7) $(CFG_MX7ULP)))
CFG_IMX_CAAM ?= y
endif
endif

# Cryptographic configuration
include core/arch/arm/plat-imx/crypto_conf.mk
