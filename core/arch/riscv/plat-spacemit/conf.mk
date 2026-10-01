# SpacemiT K1 (BananaPi BPI-F3, MusePi Pro): OP-TEE in an OpenSBI domain, reached over SBI MPXY.
PLATFORM_FLAVOR ?= k1

$(call force,CFG_RV64_core,y)

# X60 cores: RV64GCV; OP-TEE itself does not use V
$(call force,CFG_RISCV_ISA_C,y)
$(call force,CFG_RISCV_FPU,y)

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CORE_DYN_SHM,y)

CFG_DT ?= y

# No Zkr and no TRNG driver yet: software PRNG
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
$(call force,CFG_HWRNG_PTA,n)
$(call force,CFG_RISCV_ZKR_RNG,n)

$(call force,CFG_CORE_SANITIZE_KADDRESS,n)

CFG_TEE_CORE_NB_CORE ?= 8
CFG_NUM_THREADS ?= 8
$(call force,CFG_BOOT_SYNC_CPU,n)

# The PLIC S-mode contexts belong to Linux: no secure interrupts yet
$(call force,CFG_RISCV_PLIC,n)
$(call force,CFG_RISCV_APLIC,n)
$(call force,CFG_RISCV_APLIC_MSI,n)
$(call force,CFG_RISCV_IMSIC,n)

# Console through OpenSBI (DBCN): no second owner for the UART Linux uses
CFG_RISCV_SBI_CONSOLE ?= y
CFG_16550_UART ?= n

CFG_RISCV_SBI_MPXY ?= y
# One 4 KiB MPXY notification buffer per channel (2 per hart on the K1) comes from the core heap
CFG_CORE_HEAP_SIZE ?= 0x40000
CFG_RISCV_SBI_MPXY_RPMI ?= y

$(call force,CFG_RISCV_M_MODE,n)
$(call force,CFG_RISCV_S_MODE,y)
$(call force,CFG_RISCV_TIME_SOURCE_RDTIME,y)
CFG_RISCV_MTIME_RATE ?= 24000000
CFG_RISCV_SBI ?= y
CFG_RISCV_WITH_M_MODE_SM ?= y

supported-ta-targets = ta_rv64

# Secure DDR: the OpenSBI trusted-domain region of the K1 device trees (32 MiB, no-map),
# clear of the U-Boot load addresses and of the Linux CMA area at 0x40000000.
CFG_TDDRAM_START ?= 0x36000000
CFG_TDDRAM_SIZE  ?= 0x02000000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
