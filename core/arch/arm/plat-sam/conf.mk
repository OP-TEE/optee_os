PLATFORM_FLAVOR ?= sama5d2xult

include core/arch/arm/cpu/cortex-a5.mk

$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_ATMEL_UART,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
$(call force,CFG_NO_SMP,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
$(call force,CFG_AT91_MATRIX,y)

# These values are forced because of matrix configuration for secure area.
# When modifying these, always update matrix settings in
# matrix_configure_slave_h64mx().
$(call force,CFG_TZDRAM_START,0x20000000)
$(call force,CFG_TZDRAM_SIZE,0x800000)

CFG_SHMEM_START  ?= 0x21000000
CFG_SHMEM_SIZE   ?= 0x400000

CFG_TEE_RAM_VA_SIZE ?= 0x100000

CFG_DRAM_SIZE    ?= 0x20000000
