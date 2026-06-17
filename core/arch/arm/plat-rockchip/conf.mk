PLATFORM_FLAVOR ?= rk322x

$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_8250_UART,y)

CFG_DT ?= y
ifeq ($(PLATFORM_FLAVOR),rk3506)
# DTB sits in non-secure DRAM; map it secure (cf. UART0 in main.c).
CFG_MAP_EXT_DT_SECURE ?= y
endif
CFG_WITH_STATS ?= y
CFG_NUM_THREADS ?= 4

ifneq ($(PLATFORM_FLAVOR),rk322x)
CFG_DTB_MAX_SIZE ?= 0x60000
endif

ifeq ($(PLATFORM_FLAVOR),rk322x)
include ./core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)

CFG_TZDRAM_START ?= 0x68400000
CFG_TZDRAM_SIZE ?= 0x00200000
CFG_SHMEM_START ?= 0x68600000
CFG_SHMEM_SIZE ?= 0x00100000

CFG_EARLY_CONSOLE_BASE ?= UART2_BASE
CFG_EARLY_CONSOLE_SIZE ?= UART2_SIZE
CFG_EARLY_CONSOLE_BAUDRATE ?= 1500000
CFG_EARLY_CONSOLE_CLK_IN_HZ ?= 24000000
endif

ifeq ($(PLATFORM_FLAVOR),rk3399)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,6)
$(call force,CFG_ARM_GICV3,y)
CFG_CRYPTO_WITH_CE ?= y

CFG_TZDRAM_START ?= 0x30000000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_SHMEM_START  ?= 0x32000000
CFG_SHMEM_SIZE   ?= 0x00400000

CFG_EARLY_CONSOLE_BASE ?= UART2_BASE
CFG_EARLY_CONSOLE_SIZE ?= UART2_SIZE
CFG_EARLY_CONSOLE_BAUDRATE ?= 1500000
CFG_EARLY_CONSOLE_CLK_IN_HZ ?= 24000000
endif

ifeq ($(PLATFORM_FLAVOR),px30)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_CRYPTO_WITH_CE ?= y

CFG_TZDRAM_START ?= 0x30000000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_SHMEM_START  ?= 0x32000000
CFG_SHMEM_SIZE   ?= 0x00400000
endif

ifeq ($(PLATFORM_FLAVOR),rk3506)
include ./core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_TEE_CORE_NB_CORE,3)

# SMP via the OP-TEE-provided ARM32 PSCI back end: the kernel DT uses
# enable-method = "psci" / method = "smc", so OP-TEE implements CPU_ON
# (psci_rk3506.c), as the upstream rk322x port does.
# CFG_BOOT_SECONDARY_REQUEST exports boot_set_core_ns_entry() for it.
$(call force,CFG_PSCI_ARM32,y)
$(call force,CFG_BOOT_SECONDARY_REQUEST,y)

# The RK3506B boot chain leaves CNTVOFF at its reset value; sm_init()
# zeroes it (Monitor mode, SCR.NS=1) on every core via this option, so
# the non-secure virtual counter starts aligned with the physical one.
$(call force,CFG_INIT_CNTVOFF,y)

# TZDRAM can start at a 4 KiB-aligned address, which the ARMv7
# short-descriptor MMU (1 MiB sections) cannot describe; Cortex-A7
# supports LPAE (4 KiB granularity).
$(call force,CFG_WITH_LPAE,y)

# CFG_CORE_ASLR is left at its global default (y, see mk/config.mk) for
# security hardening; it is not required by this port. The early console
# survives the MMU-enable transition via the standard io_pa_or_va()
# remap of its MEM_AREA_IO_SEC mapping (see main.c), not via the ASLR
# relocation path's console re-init.

# Memory layout. Board = 512 MB DRAM at [0, 0x20000000).
# CFG_RK3506_TEE_HW_ISOLATE selects the secure-RAM placement:
#  - n (default): software isolated via reservation in DT, 32 MB.
#    FW_DDR left open; the secure RAM kept off the NS world.
#  - y: hardware isolated via FW_DDR slot-0, 16 MB.
#    Requires matching U-Boot memory-map patch
#    so the NS boot structures sit above the protected region.
CFG_RK3506_TEE_HW_ISOLATE ?= n
ifeq ($(CFG_RK3506_TEE_HW_ISOLATE),y)
CFG_TZDRAM_START ?= 0x00001000
CFG_TZDRAM_SIZE  ?= 0x01000000
else
CFG_TZDRAM_START ?= 0x18000000
CFG_TZDRAM_SIZE  ?= 0x02000000
endif

# Register the full non-secure DRAM; OP-TEE carves the secure TEE_RAM
# out of this range and accepts the remainder as non-secure.
CFG_DRAM_BASE    ?= 0x00000000
CFG_DRAM_SIZE    ?= 0x20000000

# Non-secure entry = the FIT `uboot` load address (U-Boot proper is PIE
# and self-relocates), so it must equal that load address. HW-isolate
# places U-Boot clear of the protected low region.
ifeq ($(CFG_RK3506_TEE_HW_ISOLATE),y)
CFG_NS_ENTRY_ADDR ?= 0x01100000
else
CFG_NS_ENTRY_ADDR ?= 0x00400000
endif

# Shared memory, well clear of the early-boot low DRAM.
CFG_SHMEM_START  ?= 0x10000000
CFG_SHMEM_SIZE   ?= 0x00080000

# Early console: UART0 (115200, 24 MHz xin), already clocked + muxed by
# the SPL. This is the board debug console (U-Boot CONFIG_DEBUG_UART_BASE,
# kernel earlycon uart8250,mmio32,0xff0a0000 and ttyFIQ0 / fiq-debugger
# serial-id 0 all target UART0). The main.c console MEM_AREA mapping is
# gated on it.
CFG_EARLY_CONSOLE ?= y
CFG_EARLY_CONSOLE_BASE ?= UART0_BASE
CFG_EARLY_CONSOLE_SIZE ?= UART0_SIZE
CFG_EARLY_CONSOLE_BAUDRATE ?= 115200
CFG_EARLY_CONSOLE_CLK_IN_HZ ?= 24000000
endif

ifeq ($(PLATFORM_FLAVOR),rk3588)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_AUTO_MAX_PA_BITS,y)
$(call force,CFG_CRYPTO_WITH_CE,y)
$(call force,CFG_ROCKCHIP_OTP,y)

CFG_RK_SECURE_BOOT ?= y
# Disable CFG_RK_SECURE_BOOT_SIMULATION to actually fuse the hash into the OTP.
# Enabling this option is necessary to actually enable secure boot, but may
# potentially brick your device.
CFG_RK_SECURE_BOOT_SIMULATION ?= y

CFG_TZDRAM_START ?= 0x30000000
CFG_TZDRAM_SIZE ?= 0x02000000
CFG_SHMEM_START ?= 0x32000000
CFG_SHMEM_SIZE ?= 0x00400000

CFG_EARLY_CONSOLE_BASE ?= UART2_BASE
CFG_EARLY_CONSOLE_SIZE ?= UART2_SIZE
CFG_EARLY_CONSOLE_BAUDRATE ?= 1500000
CFG_EARLY_CONSOLE_CLK_IN_HZ ?= 24000000
endif

ifeq ($(PLATFORM_FLAVOR),rk3576)
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_AUTO_MAX_PA_BITS,y)

CFG_TZDRAM_START ?= 0x70000000
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_SHMEM_START  ?= 0x72000000
CFG_SHMEM_SIZE   ?= 0x00400000
endif

ifeq ($(platform-flavor-armv8),1)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
ta-targets = ta_arm64
endif

# Default the early console off; flavors that need it (rk3506) enable it above.
CFG_EARLY_CONSOLE ?= n
