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
CFG_CAAM_DBG ?= 0x2

#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x1000)

$(call force, CFG_JR_INDEX,0)  # Default JR index used
$(call force, CFG_JR_IRQ,137)  # Default JR IT Number (105 + 32) = 137

#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER), y)
#
# Define this variable if the system is able to manage the
# DTB Modification
#
ifeq ($(CFG_DT), y)
CFG_CAAM_DT ?= y
endif

#
# Definition of all HW accelerations for all i.MX
#
$(call force, CFG_CRYPTO_RNG_HW, y)

ifeq ($(CFG_CRYPTO_RNG_HW), y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)
endif

# Force to 'y' the CFG_CRYPTO_xxx_HW to enable the CAAM HW driver
# and enable the associated CFG_CRYPTO_DRV_xxx Crypto driver
# API
#
# Example: Enable CFG_CRYPTO_DRV_HASH qnd CFG_CRYPTO_HASH_HW
#     $(eval $(call cryphw-enable-drv-hw, HASH))
define cryphw-enable-drv-hw
_var := $(strip $(1))
$$(call force, CFG_CRYPTO_$$(_var)_HW, y)
$$(call force, CFG_CRYPTO_DRV_$$(_var), y)
endef

# Definition of the HW and Cryto Driver Algorithm supported by all i.MX
$(eval $(call cryphw-enable-drv-hw, HASH))

endif
