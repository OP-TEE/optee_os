CFG_CRYPTO ?= y
# Select small code size in the crypto library if applicable (for instance
# LibTomCrypt has -DLTC_SMALL_CODE)
# Note: the compiler flag -Os is not set here but by CFG_CC_OPT_LEVEL
CFG_CRYPTO_SIZE_OPTIMIZATION ?= y

ifeq (y,$(CFG_CRYPTO))

# Ciphers
CFG_CRYPTO_AES ?= y
CFG_CRYPTO_DES ?= y
CFG_CRYPTO_SM4 ?= y

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
# Instead of calling the AES CBC encryption function for each 16 byte block of
# input, bundle a maximum of N blocks when possible. A maximum of N*16 bytes of
# temporary data are allocated on the heap.
# Minimum value is 1.
CFG_CRYPTO_CBC_MAC_BUNDLE_BLOCKS ?= 64

# Hashes
CFG_CRYPTO_MD5 ?= y
CFG_CRYPTO_SHA1 ?= y
CFG_CRYPTO_SHA224 ?= y
CFG_CRYPTO_SHA256 ?= y
CFG_CRYPTO_SHA384 ?= y
CFG_CRYPTO_SHA512 ?= y
CFG_CRYPTO_SHA512_256 ?= y
CFG_CRYPTO_SM3 ?= y

# Asymmetric ciphers
CFG_CRYPTO_DSA ?= y
CFG_CRYPTO_RSA ?= y
CFG_CRYPTO_DH ?= y
# ECC includes ECDSA and ECDH
CFG_CRYPTO_ECC ?= y
CFG_CRYPTO_SM2_PKE ?= y
CFG_CRYPTO_SM2_DSA ?= y
CFG_CRYPTO_SM2_KEP ?= y

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

CFG_CRYPTO_SHA256_ARM_CE ?= $(CFG_CRYPTO_SHA256)
CFG_CORE_CRYPTO_SHA256_ACCEL ?= $(CFG_CRYPTO_SHA256_ARM_CE)
CFG_CRYPTO_SHA1_ARM_CE ?= $(CFG_CRYPTO_SHA1)
CFG_CORE_CRYPTO_SHA1_ACCEL ?= $(CFG_CRYPTO_SHA1_ARM_CE)
CFG_CRYPTO_AES_ARM_CE ?= $(CFG_CRYPTO_AES)
CFG_CORE_CRYPTO_AES_ACCEL ?= $(CFG_CRYPTO_AES_ARM_CE)

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
ifeq ($(CFG_CRYPTO_SHA1_ARM_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_SHA1_ARM_CE)
endif
ifeq ($(CFG_CRYPTO_AES_ARM_CE),y)
$(call force,CFG_WITH_VFP,y,required by CFG_CRYPTO_AES_ARM_CE)
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
# SM2 is Elliptic Curve Cryptography, it uses some generic ECC functions
$(eval $(call cryp-dep-one, SM2_PKE, ECC))
$(eval $(call cryp-dep-one, SM2_DSA, ECC))
$(eval $(call cryp-dep-one, SM2_KEP, ECC))

###############################################################
# libtomcrypt (LTC) specifics, phase #1
# LTC is only configured via _CFG_CORE_LTC_ prefixed variables
#
# _CFG_CORE_LTC_xxx_DESC means that LTC will only register the
# descriptor of the algorithm, not provide a
# crypt_xxx_alloc_ctx() function.
###############################################################

# If LTC is the cryptolib, pull configuration from CFG_CRYPTO_xxx
ifeq ($(CFG_CRYPTOLIB_NAME),tomcrypt)
# dsa_make_params() needs all three SHA-2 algorithms.
# Disable DSA if any is missing.
$(eval $(call cryp-dep-all, DSA, SHA256 SHA384 SHA512))

# Assign _CFG_CORE_LTC_xxx based on CFG_CRYPTO_yyy
core-ltc-vars = AES DES
core-ltc-vars += ECB CBC CTR CTS XTS
core-ltc-vars += MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA512_256
core-ltc-vars += HMAC CMAC CBC_MAC
core-ltc-vars += CCM
ifeq ($(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB),y)
core-ltc-vars += GCM
endif
core-ltc-vars += RSA DSA DH ECC
core-ltc-vars += SIZE_OPTIMIZATION
core-ltc-vars += SM2_PKE
core-ltc-vars += SM2_DSA
core-ltc-vars += SM2_KEP
# Assigned selected CFG_CRYPTO_xxx as _CFG_CORE_LTC_xxx
$(foreach v, $(core-ltc-vars), $(eval _CFG_CORE_LTC_$(v) := $(CFG_CRYPTO_$(v))))
_CFG_CORE_LTC_MPI := $(CFG_CORE_MBEDTLS_MPI)
_CFG_CORE_LTC_AES_ACCEL := $(CFG_CORE_CRYPTO_AES_ACCEL)
_CFG_CORE_LTC_SHA1_ACCEL := $(CFG_CORE_CRYPTO_SHA1_ACCEL)
_CFG_CORE_LTC_SHA256_ACCEL := $(CFG_CORE_CRYPTO_SHA256_ACCEL)
endif

###############################################################
# mbedtls specifics
###############################################################

ifeq ($(CFG_CRYPTOLIB_NAME),mbedtls)
# mbedtls has to be complemented with some algorithms by LTC
# Specify the algorithms here
_CFG_CORE_LTC_DSA := $(CFG_CRYPTO_DSA)
_CFG_CORE_LTC_MPI := $(CFG_CRYPTO_DSA)
_CFG_CORE_LTC_SHA256_DESC := $(CFG_CRYPTO_DSA)
_CFG_CORE_LTC_SHA384_DESC := $(CFG_CRYPTO_DSA)
_CFG_CORE_LTC_SHA512_DESC := $(CFG_CRYPTO_DSA)
_CFG_CORE_LTC_XTS := $(CFG_CRYPTO_XTS)
_CFG_CORE_LTC_CCM := $(CFG_CRYPTO_CCM)
_CFG_CORE_LTC_AES_DESC := $(call cfg-one-enabled, CFG_CRYPTO_XTS CFG_CRYPTO_CCM)
endif

###############################################################
# libtomcrypt (LTC) specifics, phase #2
###############################################################

_CFG_CORE_LTC_SHA256_DESC := $(call cfg-one-enabled, _CFG_CORE_LTC_SHA256_DESC \
						     _CFG_CORE_LTC_SHA224 \
						     _CFG_CORE_LTC_SHA256)
_CFG_CORE_LTC_SHA384_DESC := $(call cfg-one-enabled, _CFG_CORE_LTC_SHA384_DESC \
						     _CFG_CORE_LTC_SHA384)
_CFG_CORE_LTC_SHA512_DESC := $(call cfg-one-enabled, _CFG_CORE_LTC_SHA512_DESC \
						     _CFG_CORE_LTC_SHA512_256 \
						     _CFG_CORE_LTC_SHA512)
_CFG_CORE_LTC_AES_DESC := $(call cfg-one-enabled, _CFG_CORE_LTC_AES_DESC \
						  _CFG_CORE_LTC_AES)

# Assign system variables
_CFG_CORE_LTC_CE := $(CFG_CRYPTO_WITH_CE)
_CFG_CORE_LTC_VFP := $(CFG_WITH_VFP)
_CFG_CORE_LTC_BIGNUM_MAX_BITS := $(CFG_CORE_BIGNUM_MAX_BITS)
_CFG_CORE_LTC_PAGER := $(CFG_WITH_PAGER)
ifneq ($(CFG_NUM_THREADS),1)
_CFG_CORE_LTC_OPTEE_THREAD := y
else
_CFG_CORE_LTC_OPTEE_THREAD := n
endif
_CFG_CORE_LTC_HWSUPP_PMULL := $(CFG_HWSUPP_PMULL)

# Assign aggregated variables
ltc-one-enabled = $(call cfg-one-enabled,$(foreach v,$(1),_CFG_CORE_LTC_$(v)))
_CFG_CORE_LTC_ACIPHER := $(call ltc-one-enabled, RSA DSA DH ECC)
_CFG_CORE_LTC_AUTHENC := $(and $(filter y,$(_CFG_CORE_LTC_AES_DESC)), \
			       $(filter y,$(call ltc-one-enabled, CCM GCM)))
_CFG_CORE_LTC_CIPHER := $(call ltc-one-enabled, AES_DESC DES)
_CFG_CORE_LTC_HASH := $(call ltc-one-enabled, MD5 SHA1 SHA224 SHA256 SHA384 \
					      SHA512)
_CFG_CORE_LTC_MAC := $(call ltc-one-enabled, HMAC CMAC CBC_MAC)
_CFG_CORE_LTC_CBC := $(call ltc-one-enabled, CBC CBC_MAC)
_CFG_CORE_LTC_ASN1 := $(call ltc-one-enabled, RSA DSA ECC)

###############################################################
# Platform independent crypto-driver configuration
###############################################################
CRYPTO_MAKEFILES := $(sort $(wildcard core/drivers/crypto/*/crypto.mk))
include $(CRYPTO_MAKEFILES)

# Enable TEE_ALG_RSASSA_PKCS1_V1_5 algorithm for signing with PKCS#1 v1.5 EMSA
# without ASN.1 around the hash.
ifeq ($(CFG_CRYPTOLIB_NAME),tomcrypt)
CFG_CRYPTO_RSASSA_NA1 ?= y
endif
