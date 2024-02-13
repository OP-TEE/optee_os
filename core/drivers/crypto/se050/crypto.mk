ifeq ($(CFG_NXP_SE05X),y)
# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

# SE050 initialization
# Some secure elements can only be accessed over an SCP03 enabled session.
# Some of the NXP SE05X devices fall in this category (i.e NXP SE050F).
# Only enable this configuration to support those systems.
CFG_CORE_SCP03_ONLY ?= n
# Rotate the SCP03 keys during SCP03 init (does not require user intervention).
# CAUTION: the provisioning configuration chosen might require a stable HUK.
CFG_CORE_SE05X_SCP03_PROVISION_ON_INIT ?= n
# Rotate the SCP03 keys via PTA (request from Normal World).
CFG_CORE_SE05X_SCP03_PROVISION ?= n
# The Provision request will rotate the SCP03 keys back to its factory settings.
CFG_CORE_SE05X_SCP03_PROVISION_WITH_FACTORY_KEYS ?= n
# CAUTION: Leaks the SCP03 keys that are going to be programmed on the device's
# NVM during a provisioning operation.
CFG_CORE_SE05X_DISPLAY_SCP03_KEYS ?= n
# Displays the SE050 device information on the console at boot (i.e. OEFID)
CFG_CORE_SE05X_DISPLAY_INFO ?= y
# Enables SCP03 protocol during boot (does not require user intervention)
CFG_CORE_SE05X_SCP03_EARLY ?= y
# CAUTION: Deletes all persistent storage (keys/certs) from the SE05X at boot
CFG_CORE_SE05X_INIT_NVM ?= n
# Prevents the deletion of the secure storage object holding a reference to a
# Secure Element (SE) Non Volatile Memory object unless there is explicit
# confirmation from the SE that the NVM object has been removed.
CFG_CORE_SE05X_BLOCK_OBJ_DEL_ON_ERROR ?= n
# Select the SE05X applet version for aligning the built-in features
CFG_CORE_SE05X_VER ?= 03_XX

# I2C bus baudrate (depends on SoC)
CFG_CORE_SE05X_BAUDRATE ?= 3400000
# I2C bus [0..2] (depends on board)
CFG_CORE_SE05X_I2C_BUS ?= 2
# I2C access via REE after TEE boot
CFG_CORE_SE05X_I2C_TRAMPOLINE ?= y

# Extra stacks required to support the Plug and Trust external library
ifeq ($(shell test $(CFG_STACK_THREAD_EXTRA) -lt 8192; echo $$?), 0)
$(error Error: SE050 requires CFG_STACK_THREAD_EXTRA at least 8192)
endif
ifeq ($(shell test $(CFG_STACK_TMP_EXTRA) -lt 8192; echo $$?), 0)
$(error Error: SE050 requires CFG_STACK_TMP_EXTRA at least 8192)
endif

# SE05X Die Identifier
CFG_NXP_SE05X_DIEID_DRV ?= y

# Allow a secure client to enable the SCP03 session
CFG_NXP_SE05X_SCP03_DRV ?= y
ifeq ($(CFG_NXP_SE05X_SCP03_DRV),y)
$(call force,CFG_SCP03_PTA,y,Mandated by CFG_NXP_SE05X_SCP03)
endif

# Allow a secure client to send APDU raw frames
CFG_NXP_SE05X_APDU_DRV ?= y
ifeq ($(CFG_NXP_SE05X_APDU_DRV),y)
$(call force,CFG_APDU_PTA,y,Mandated by CFG_NXP_SE05X_APDU)
endif

# Random Number Generator
CFG_NXP_SE05X_RNG_DRV ?= y
ifeq ($(CFG_NXP_SE05X_RNG_DRV),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
endif

se050-one-enabled = $(call cfg-one-enabled, \
                        $(foreach v,$(1), CFG_NXP_SE05X_$(v)_DRV))
# Asymmetric ciphers
CFG_NXP_SE05X_RSA_DRV ?= y
CFG_NXP_SE05X_RSA_DRV_FALLBACK ?= n
CFG_NXP_SE05X_ECC_DRV ?= y
CFG_NXP_SE05X_ECC_DRV_FALLBACK ?= n
$(call force,CFG_NXP_SE05X_ACIPHER_DRV,$(call se050-one-enabled,RSA ECC))

# Asymmetric driver
ifeq ($(CFG_NXP_SE05X_ACIPHER_DRV),y)
$(call force,CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_NXP_SE05X_ACIPHER_DRV)
endif

# Asymmetric ciphers configuration
# - RSA
ifeq ($(CFG_NXP_SE05X_RSA_DRV),y)
$(call force,CFG_CRYPTO_DRV_RSA,y)
CFG_CRYPTO_RSASSA_NA1 ?= y
endif
# - ECC
ifeq ($(CFG_NXP_SE05X_ECC_DRV),y)
$(call force,CFG_CRYPTO_DRV_ECC,y)
endif

# Symmetric ciphers
CFG_NXP_SE05X_CTR_DRV ?= y
$(call force,CFG_NXP_SE05X_CIPHER_DRV,$(call se050-one-enabled,CTR))

# Symmetric driver
ifeq ($(CFG_NXP_SE05X_CIPHER_DRV),y)
$(call force,CFG_CRYPTO_DRV_CIPHER,y,Mandated by CFG_NXP_SE05X_CIPHER_DRV)
endif

endif  # CFG_NXP_SE05X
