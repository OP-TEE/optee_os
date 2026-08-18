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

# When enabled, embed support for CKM_RSA_X_509 (a.k.a. Raw RSA) ciphering
# and authentication. The feature can be needed for some TLS v1.2 connections.
# Raw RSA can be unsafe if client uses a weak clear data padding scheme.
CFG_PKCS11_TA_RSA_X_509 ?= n

# When enabled, implement a TA command to wipe all PKCS#11 TA persistent storage.
CFG_PKCS11_TA_WIPE_STORAGE ?= n

# Restrict the PKCS11_CMD_WIPE_STORAGE command to callers whose TEE client
# identity login type is TEE_LOGIN_REE_KERNEL (i.e. REE kernel module clients).
CFG_PKCS11_TA_WIPE_STORAGE_REQUIRES_KERNEL ?= y

global-incdirs-y += include
global-incdirs-y += src
subdirs-y += src
