#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug: define 3x32 bits value (same bit used to debug a module)
# CFG_DBG_CAAM_TRACE  Module print trace
# CFG_DBG_CAAM_DESC   Module descriptor dump
# CFG_DBG_CAAM_BUF    Module buffer dump
#
# DBG_HAL    BIT32(0)  // HAL trace
# DBG_CTRL   BIT32(1)  // Controller trace
# DBG_MEM    BIT32(2)  // Memory utility trace
# DBG_SGT    BIT32(3)  // Scatter Gather trace
# DBG_PWR    BIT32(4)  // Power trace
# DBG_JR     BIT32(5)  // Job Ring trace
# DBG_RNG    BIT32(6)  // RNG trace
# DBG_HASH   BIT32(7)  // Hash trace
CFG_DBG_CAAM_TRACE ?= 0x2
CFG_DBG_CAAM_DESC ?= 0x0
CFG_DBG_CAAM_BUF ?= 0x0

#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x1000)

$(call force, CFG_JR_INDEX,0)  # Default JR index used
$(call force, CFG_JR_INT,137)  # Default JR IT Number (105 + 32) = 137

#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER), y)

$(call force, CFG_NXP_CAAM_RUNTIME_JR, y)

#
# Definition of all HW accelerations for all i.MX
#
$(call force, CFG_NXP_CAAM_RNG_DRV, y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)

# Force to 'y' the CFG_NXP_CAAM_xxx_DRV to enable the CAAM HW driver
# and enable the associated CFG_CRYPTO_DRV_xxx Crypto driver
# API
#
# Example: Enable CFG_CRYPTO_DRV_HASH and CFG_NXP_CAAM_HASH_DRV
#     $(eval $(call cryphw-enable-drv-hw, HASH))
define cryphw-enable-drv-hw
_var := $(strip $(1))
$$(call force, CFG_NXP_CAAM_$$(_var)_DRV, y)
$$(call force, CFG_CRYPTO_DRV_$$(_var), y)
endef

# Definition of the HW and Cryto Driver Algorithm supported by all i.MX
$(eval $(call cryphw-enable-drv-hw, HASH))

endif
