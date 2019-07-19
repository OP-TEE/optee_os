#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug Trace
#
# DBG_TRACE_HAL    BIT32(0)  // HAL trace
# DBG_TRACE_CTRL   BIT32(1)  // Controller trace
# DBG_TRACE_MEM    BIT32(2)  // Memory utility trace
# DBG_TRACE_PWR    BIT32(3)  // Power trace
# DBG_TRACE_JR     BIT32(4)  // Job Ring trace
# DBG_DESC_JR      BIT32(5)  // Job Ring dump descriptor
# DBG_TRACE_RNG    BIT32(6)  // RNG trace
# DBG_DESC_RNG     BIT32(7)  // RNG dump descriptor
# DBG_TRACE_HASH   BIT32(8)  // Hash trace
# DBG_DESC_HASH    BIT32(9)  // Hash dump descriptor
# DBG_BUF_HASH     BIT32(10) // Hash dump Buffer
# DBG_TRACE_CIPHER BIT32(11) // Cipher trace
# DBG_DESC_CIPHER  BIT32(12) // Cipher dump descriptor
# DBG_BUF_CIPHER   BIT32(13) // Cipher dump Buffer
# DBG_TRACE_ECC    BIT32(14) // ECC trace
# DBG_DESC_ECC     BIT32(15) // ECC dump descriptor
# DBG_BUF_ECC      BIT32(16) // ECC dump Buffer
# DBG_TRACE_BLOB   BIT32(17) // BLOB trace
# DBG_DESC_BLOB    BIT32(18) // BLOB dump descriptor
# DBG_BUF_BLOB     BIT32(19) // BLOB dump Buffer
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
$(call force, CFG_CRYPTO_RNG_HW,y)

ifeq ($(CFG_CRYPTO_RNG_HW), y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)
else
$(call force, CFG_WITH_SOFTWARE_PRNG,y)
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

# Return 'y' if at least one of the variable
# CFG_CRYPTO_xxx_HW is 'y'
cryphw-one-enabled = $(call cfg-one-enabled, \
                        $(foreach v,$(1), CFG_CRYPTO_$(v)_HW))


# Definition of the HW and Cryto Driver Algorithm supported by all i.MX
$(eval $(call cryphw-enable-drv-hw, HASH))
$(eval $(call cryphw-enable-drv-hw, CIPHER))
$(eval $(call cryphw-enable-drv-hw, ECC))
$(eval $(call cryphw-enable-drv-hw, HUK))

$(call force, CFG_CRYPTO_ACIPHER_HW, $(call cryphw-one-enabled, ECC))
$(call force, CFG_CRYPTO_BLOB_HW, $(call cryphw-one-enabled, HUK))

#
# Enable Cryptographic Driver interface
#
CFG_CRYPTO_DRV_ACIPHER ?= $(CFG_CRYPTO_ACIPHER_HW)

endif
