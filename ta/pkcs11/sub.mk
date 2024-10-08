# Enable PKCS#11 TA's C_DigestKey support
CFG_PKCS11_TA_ALLOW_DIGEST_KEY ?= y

# Enable PKCS#11 TA's TEE Identity based authentication support
CFG_PKCS11_TA_AUTH_TEE_IDENTITY ?= y

# PKCS#11 TA heap size can be customized if 32kB is not enough
CFG_PKCS11_TA_HEAP_SIZE ?= (32 * 1024)

# Defines the number of PKCS11 token implemented by the PKCS11 TA
CFG_PKCS11_TA_TOKEN_COUNT ?= 3

# When enabled, embed support for object checksum value computation
CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE ?= y

# Locks correspondingly User or SO PIN when reaching maximum
# failed authentication attemps (continous) limit
CFG_PKCS11_TA_LOCK_PIN_AFTER_FAILED_LOGIN_ATTEMPTS ?= y

global-incdirs-y += include
global-incdirs-y += src
subdirs-y += src
