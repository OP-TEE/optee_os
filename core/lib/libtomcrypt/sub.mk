CFG_CRYPTO ?= y

ifeq (y,$(CFG_CRYPTO))

# Ciphers
CFG_CRYPTO_AES ?= y
CFG_CRYPTO_DES ?= y

# Cipher block modes
CFG_CRYPTO_ECB ?= y
CFG_CRYPTO_CBC ?= y
CFG_CRYPTO_CTR ?= y
CFG_CRYPTO_CTS ?= y
CFG_CRYPTO_XTS ?= y

# Message authentication codes
CFG_CRYPTO_HMAC ?= y
CFG_CRYPTO_CMAC ?= y
CFG_CRYPTO_CBC_MAC ?= y

# Hashes
CFG_CRYPTO_MD5 ?= y
CFG_CRYPTO_SHA1 ?= y
CFG_CRYPTO_SHA224 ?= y
CFG_CRYPTO_SHA256 ?= y
CFG_CRYPTO_SHA384 ?= y
CFG_CRYPTO_SHA512 ?= y

# Asymmetric ciphers
CFG_CRYPTO_DSA ?= y
CFG_CRYPTO_RSA ?= y
CFG_CRYPTO_DH ?= y

# Authenticated encryption
CFG_CRYPTO_CCM ?= y
CFG_CRYPTO_GCM ?= y

endif

ifeq ($(CFG_WITH_PAGER),y)
ifneq ($(CFG_CRYPTO_SHA256),y)
ifneq ($(CFG_CRYPTO_SHA256_ARM32_CE),y)
$(warning Warning: Enabling CFG_CRYPTO_SHA256 [required by CFG_WITH_PAGER])
CFG_CRYPTO_SHA256:=y
endif
endif
endif

# Dependency checks: warn and disable some features if dependencies are not met

cryp-dep-one = $(call cfg-depends-one,CFG_CRYPTO_$(strip $(1)),$(patsubst %, CFG_CRYPTO_%,$(strip $(2))))
cryp-dep-all = $(call cfg-depends-all,CFG_CRYPTO_$(strip $(1)),$(patsubst %, CFG_CRYPTO_%,$(strip $(2))))

$(eval $(call cryp-dep-one, ECB, AES DES))
$(eval $(call cryp-dep-one, CBC, AES DES))
$(eval $(call cryp-dep-one, CTR, AES))
# CTS is implemented with ECB and CBC
$(eval $(call cryp-dep-all, CTS, AES ECB CBC))
$(eval $(call cryp-dep-one, XTS, AES))
$(eval $(call cryp-dep-one, HMAC, AES DES))
$(eval $(call cryp-dep-one, HMAC, MD5 SHA1 SHA224 SHA256 SHA384 SHA512))
$(eval $(call cryp-dep-one, CMAC, AES))
$(eval $(call cryp-dep-one, CBC_MAC, AES DES))
$(eval $(call cryp-dep-one, CCM, AES))
$(eval $(call cryp-dep-one, GCM, AES))
# If no AES cipher mode is left, disable AES
$(eval $(call cryp-dep-one, AES, ECB CBC CTR CTS XTS))
# If no DES cipher mode is left, disable DES
$(eval $(call cryp-dep-one, DES, ECB CBC))

cryp-one-enabled = $(call cfg-one-enabled,$(foreach v,$(1),CFG_CRYPTO_$(v)))

_CFG_CRYPTO_WITH_ACIPHER := $(call cryp-one-enabled, RSA DSA DH)
_CFG_CRYPTO_WITH_AUTHENC := $(and $(filter y,$(CFG_CRYPTO_AES)), $(call cryp-one-enabled, CCM GCM))
_CFG_CRYPTO_WITH_CIPHER := $(call cryp-one-enabled, AES DES)
_CFG_CRYPTO_WITH_HASH := $(call cryp-one-enabled, MD5 SHA1 SHA224 SHA256 SHA384 SHA512)
_CFG_CRYPTO_WITH_MAC := $(call cryp-one-enabled, HMAC CMAC CBC_MAC)
_CFG_CRYPTO_WITH_CBC := $(call cryp-one-enabled, CBC CBC_MAC)
_CFG_CRYPTO_WITH_ASN1 := $(call cryp-one-enabled, RSA DSA)

cppflags-lib-$(libtomcrypt_with_optimize_size) += -DLTC_SMALL_CODE -DLTC_NO_FAST

global-incdirs-y += include

subdirs-y += src
