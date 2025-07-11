PLATFORM_FLAVOR ?= cv64a6_genesys_2

ifeq ($(PLATFORM_FLAVOR),cv64a6_genesys_2)
$(call force,CFG_RV64_core,y)
$(call force,CFG_RISCV_FPU,y)
$(call force,CFG_RISCV_MMU_MODE,39)
supported-ta-targets = ta_rv64
endif

ifeq ($(PLATFORM_FLAVOR),cv32a6_genesys_2)
$(call force,CFG_RV32_core,y)
$(call force,CFG_RISCV_FPU,n)
$(call force,CFG_RISCV_MMU_MODE,32)
supported-ta-targets = ta_rv32
endif

$(call force,CFG_RISCV_ISA_C,y)

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CORE_DYN_SHM,y)

$(call force,CFG_DYN_CONFIG,n)

CFG_DT ?= y

$(call force,CFG_WITH_SOFTWARE_PRNG,y)

$(call force,CFG_CORE_ASLR,n)
$(call force,CFG_CORE_SANITIZE_KADDRESS,n)

$(call force,CFG_TEE_CORE_NB_CORE, 1)
$(call force,CFG_NUM_THREADS, 1)
$(call force,CFG_BOOT_SYNC_CPU,n)

CFG_RISCV_PLIC ?= y
$(call force,CFG_RISCV_APLIC,n)
$(call force,CFG_RISCV_APLIC_MSI,n)
$(call force,CFG_RISCV_IMSIC,n)

CFG_RISCV_SBI_CONSOLE ?= n
CFG_16550_UART ?= y

$(call force,CFG_RISCV_M_MODE,n)
$(call force,CFG_RISCV_S_MODE,y)
$(call force,CFG_RISCV_TIME_SOURCE_RDTIME,y)
CFG_RISCV_MTIME_RATE ?= 10000000
CFG_RISCV_SBI ?= y
CFG_RISCV_WITH_M_MODE_SM ?= y

CFG_TDDRAM_START ?= 0xBE000000
CFG_TDDRAM_SIZE  ?= 0x01000000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
