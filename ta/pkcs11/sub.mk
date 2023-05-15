# Enable PKCS#11 TA's C_DigestKey support
CFG_PKCS11_TA_ALLOW_DIGEST_KEY ?= y

# Enable PKCS#11 TA's TEE Identity based authentication support
CFG_PKCS11_TA_AUTH_TEE_IDENTITY ?= y

# PKCS#11 TA heap size can be customized if 32kB is not enough
CFG_PKCS11_TA_HEAP_SIZE ?= (32 * 1024)

# Defines the number of PKCS11 token implemented by the PKCS11 TA
CFG_PKCS11_TA_TOKEN_COUNT ?= 3

global-incdirs-y += include
global-incdirs-y += src
subdirs-y += src
