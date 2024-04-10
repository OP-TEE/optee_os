$(call force,CFG_RV64_core,y)

$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_TEE_CORE_DEBUG,n)
$(call force,CFG_CORE_DYN_SHM,n)

CFG_DT ?= y

# Crypto flags
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
$(call force,CFG_HWRNG_PTA,y)
$(call force,CFG_HWRNG_QUALITY,1024)
$(call force,CFG_RISCV_ZKR_RNG,y)

# Protection flags
$(call force,CFG_CORE_ASLR,n)
$(call force,CFG_WITH_STACK_CANARIES,n)
$(call force,CFG_CORE_SANITIZE_KADDRESS,n)

# Hart-related flags
CFG_TEE_CORE_NB_CORE ?= 1
CFG_NUM_THREADS ?= 1
$(call force,CFG_BOOT_SYNC_CPU,y)

# RISC-V-specific flags
rv64-platform-isa ?= rv64imafdc_zicsr_zifencei

$(call force,CFG_RISCV_M_MODE,n)
$(call force,CFG_RISCV_S_MODE,y)
$(call force,CFG_RISCV_PLIC,y)
$(call force,CFG_SBI_CONSOLE,n)
$(call force,CFG_16550_UART,y)
$(call force,CFG_RISCV_TIME_SOURCE_RDTIME,y)
CFG_RISCV_MTIME_RATE ?= 10000000
CFG_RISCV_SBI ?= y
CFG_RISCV_WITH_M_MODE_SM ?= y

# TA-related flags
supported-ta-targets = ta_rv64

# Memory layout flags
CFG_TDDRAM_START ?= 0x8e000000
CFG_TDDRAM_SIZE  ?= 0x00f00000
$(call force,CFG_CORE_RESERVED_SHM,y)
CFG_SHMEM_START  ?= 0x88f00000
CFG_SHMEM_SIZE   ?= 0x00200000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
