PLATFORM_FLAVOR ?= zcu102

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_CDNS_UART,y)
$(call force,CFG_GIC,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as ATF does not provide a
#    DTB to OP-TEE. Hardware RNG is also not currently supported.
# 2. OP-TEE does not boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)

# ZynqMP supports up to 40 bits of physical addresses
CFG_CORE_ARM64_PA_BITS ?= 40
else
$(call force,CFG_ARM32_core,y)
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),zcu102 zc1751_dc1 zc1751_dc2))
# ZCU102 features 4 GiB of DDR
ifeq ($(CFG_ARM64_core),y)
CFG_DDR_SIZE ?= 0x100000000
else
# On 32 bit build limit to 2 GiB of RAM
CFG_DDR_SIZE ?= 0x80000000
endif
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),ultra96))
# Ultra96 features 2 GiB of DDR
CFG_DDR_SIZE ?= 0x80000000
endif

# By default use DT address as specified by Xilinx
CFG_DT_ADDR ?= 0x100000

CFG_TZDRAM_START ?= 0x60000000
CFG_TZDRAM_SIZE  ?= 0x10000000
CFG_SHMEM_START  ?= 0x70000000
CFG_SHMEM_SIZE   ?= 0x10000000

CFG_WITH_STATS ?= y
CFG_CRYPTO_WITH_CE ?= y

CFG_ZYNQMP_PM ?= $(CFG_ARM64_core)

ifeq ($(CFG_RPMB_FS),y)
$(call force,CFG_ZYNQMP_HUK,y,Mandated by CFG_RPMB_FS)
endif

ifeq ($(CFG_ZYNQMP_HUK),y)
$(call force,CFG_ZYNQMP_CSU_AES,y,Mandated by CFG_ZYNQMP_HUK)
$(call force,CFG_ZYNQMP_CSU_PUF,y,Mandated by CFG_ZYNQMP_HUK)
endif

ifeq ($(CFG_ZYNQMP_CSU_AES),y)
$(call force,CFG_ZYNQMP_CSUDMA,y,Mandated by CFG_ZYNQMP_CSU_AES)
$(call force,CFG_DT,y,Mandated by CFG_ZYNQMP_CSU_AES)
endif

ifneq (,$(filter y, $(CFG_ZYNQMP_CSU_PUF) $(CFG_ZYNQMP_CSUDMA) $(CFG_ZYNQMP_CSU_AES)))
$(call force,CFG_ZYNQMP_CSU,y,Mandated by CFG_ZYNQMP_CSU* clients)
endif
