#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug Trace
#
# DBG_TRACE_HAL  BIT32(0)  // HAL trace
# DBG_TRACE_CTRL BIT32(1)  // Controller trace
# DBG_TRACE_MEM  BIT32(2)  // Memory utility trace
# DBG_TRACE_PWR  BIT32(3)  // Power trace
# DBG_TRACE_JR   BIT32(4)  // Job Ring trace
# DBG_DESC_JR    BIT32(5)  // Job Ring dump descriptor
# DBG_TRACE_RNG  BIT32(6)  // RNG trace
# DBG_DESC_RNG   BIT32(7)  // RNG dump descriptor
# DBG_TRACE_HASH BIT32(8)  // Hash trace
# DBG_DESC_HASH  BIT32(9)  // Hash dump descriptor
# DBG_BUF_HASH   BIT32(10) // Hash dump Buffer
CFG_CAAM_DBG ?= DBG_TRACE_JR | DBG_TRACE_RNG | DBG_DESC_RNG

#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force,CFG_JR_BLOCK_SIZE,0x10000)
$(call force,CFG_JR_INDEX,2)  # Default JR index used

ifneq (,$(filter $(PLATFORM_FLAVOR),ls1046ardb))
$(call force,CFG_JR_INT,137)  # Default JR IT Number (105 + 32) = 137
endif

#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER),y)

$(call force,CFG_NXP_CAAM_RUNTIME_JR,y)

#
# Definition of all HW accelerations for all LS
#
$(call force,CFG_NXP_CAAM_RNG_DRV,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)

# Force to 'y' the CFG_NXP_CAAM_xxx_DRV to enable the CAAM HW driver
# and enable the associated CFG_CRYPTO_DRV_xxx Crypto driver
# API
#
# Example: Enable CFG_CRYPTO_DRV_HASH and CFG_NXP_CAAM_HASH_DRV
#     $(eval $(call cryphw-enable-drv-hw, HASH))
define cryphw-enable-drv-hw
_var := $(strip $(1))
$$(call force,CFG_NXP_CAAM_$$(_var)_DRV,y)
$$(call force,CFG_CRYPTO_DRV_$$(_var),y)
endef

# Definition of the HW and Cryto Driver Algorithm supported by all LS
$(eval $(call cryphw-enable-drv-hw,HASH))

endif
