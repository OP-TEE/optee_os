CFG_CRYPTO ?= y
CFG_CRYPTO_SIZE_OPTIMIZATION ?= y

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
CFG_CRYPTO_SHA512_256 ?= y

# Asymmetric ciphers
CFG_CRYPTO_DSA ?= y
CFG_CRYPTO_RSA ?= y
CFG_CRYPTO_DH ?= y
CFG_CRYPTO_ECC ?= y

# Authenticated encryption
CFG_CRYPTO_CCM ?= y
CFG_CRYPTO_GCM ?= y
# Default uses the OP-TEE internal AES-GCM implementation
CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB ?= n

endif

ifeq ($(CFG_WITH_PAGER),y)
ifneq ($(CFG_CRYPTO_SHA256),y)
$(warning Warning: Enabling CFG_CRYPTO_SHA256 [required by CFG_WITH_PAGER])
CFG_CRYPTO_SHA256:=y
endif
endif

$(eval $(call cryp-enable-all-depends,CFG_WITH_SOFTWARE_PRNG, AES ECB SHA256))

ifeq ($(CFG_CRYPTO_WITH_CE),y)

$(call force,CFG_AES_GCM_TABLE_BASED,n,conflicts with CFG_CRYPTO_WITH_CE)

# CFG_HWSUPP_PMULT_64 defines whether the CPU supports polynomial multiplies
# of 64-bit values (Aarch64: PMULL/PMULL2 with the 1Q specifier; Aarch32:
# VMULL.P64). These operations are part of the Cryptographic Extensions, so
# assume they are implicitly contained in CFG_CRYPTO_WITH_CE=y.
CFG_HWSUPP_PMULT_64 ?= y

ifeq ($(CFG_ARM32_core),y)
CFG_CRYPTO_AES_ARM32_CE ?= $(CFG_CRYPTO_AES)
CFG_CRYPTO_SHA1_ARM32_CE ?= $(CFG_CRYPTO_SHA1)
CFG_CRYPTO_SHA256_ARM32_CE ?= $(CFG_CRYPTO_SHA256)
endif

ifeq ($(CFG_ARM64_core),y)
CFG_CRYPTO_AES_ARM64_CE ?= $(CFG_CRYPTO_AES)
CFG_CRYPTO_SHA1_ARM64_CE ?= $(CFG_CRYPTO_SHA1)
CFG_CRYPTO_SHA256_ARM64_CE ?= $(CFG_CRYPTO_SHA256)
endif

else #CFG_CRYPTO_WITH_CE

CFG_AES_GCM_TABLE_BASED ?= y

endif #!CFG_CRYPTO_WITH_CE


# Cryptographic extensions can only be used safely when OP-TEE knows how to
# preserve the VFP context
ifeq ($(CFG_CRYPTO_SHA256_ARM32_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_SHA256_ARM32_CE)
endif
ifeq ($(CFG_CRYPTO_SHA256_ARM64_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_SHA256_ARM64_CE)
endif
ifeq ($(CFG_CRYPTO_SHA1_ARM32_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_SHA1_ARM32_CE)
endif
ifeq ($(CFG_CRYPTO_SHA1_ARM64_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_SHA1_ARM64_CE)
endif
ifeq ($(CFG_CRYPTO_AES_ARM64_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_AES_ARM64_CE)
endif

cryp-enable-all-depends = $(call cfg-enable-all-depends,$(strip $(1)),$(foreach v,$(2),CFG_CRYPTO_$(v)))
$(eval $(call cryp-enable-all-depends,CFG_REE_FS, AES ECB CTR HMAC SHA256 GCM))
$(eval $(call cryp-enable-all-depends,CFG_RPMB_FS, AES ECB CTR HMAC SHA256 GCM))

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

# dsa_make_params() needs all three SHA-2 algorithms.
# Disable DSA if any is missing.
$(eval $(call cryp-dep-all, DSA, SHA256 SHA384 SHA512))

cryp-one-enabled = $(call cfg-one-enabled,$(foreach v,$(1),CFG_CRYPTO_$(v)))
cryp-all-enabled = $(call cfg-all-enabled,$(foreach v,$(1),CFG_CRYPTO_$(v)))

_CFG_CRYPTO_WITH_ACIPHER := $(call cryp-one-enabled, RSA DSA DH ECC)
_CFG_CRYPTO_WITH_AUTHENC := $(and $(filter y,$(CFG_CRYPTO_AES)), $(call cryp-one-enabled, CCM GCM))
_CFG_CRYPTO_WITH_CIPHER := $(call cryp-one-enabled, AES DES)
_CFG_CRYPTO_WITH_HASH := $(call cryp-one-enabled, MD5 SHA1 SHA224 SHA256 SHA384 SHA512)
_CFG_CRYPTO_WITH_MAC := $(call cryp-one-enabled, HMAC CMAC CBC_MAC)
_CFG_CRYPTO_WITH_CBC := $(call cryp-one-enabled, CBC CBC_MAC)
_CFG_CRYPTO_WITH_ASN1 := $(call cryp-one-enabled, RSA DSA ECC)
