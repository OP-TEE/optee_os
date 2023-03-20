ifeq ($(CFG_NXP_CAAM),y)
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
# DBG_RSA    BIT32(8)  // RSA trace
# DBG_CIPHER BIT32(9)  // Cipher trace
# DBG_BLOB   BIT32(10) // BLOB trace
# DBG_DMAOBJ BIT32(11) // DMA Object Trace
# DBG_ECC    BIT32(12) // ECC trace
# DBG_DH     BIT32(13) // DH Trace
# DBG_DSA    BIT32(14) // DSA trace
# DBG_MP     BIT32(15) // MP trace
CFG_DBG_CAAM_TRACE ?= 0x2
CFG_DBG_CAAM_DESC ?= 0x0
CFG_DBG_CAAM_BUF ?= 0x0

# CAAM default drivers
caam-drivers = RNG BLOB

# CAAM default drivers connected to the HW crypto API
caam-crypto-drivers = CIPHER HASH HMAC CMAC

ifneq (,$(filter $(PLATFORM_FLAVOR),ls1012ardb ls1043ardb ls1046ardb))
$(call force, CFG_CAAM_BIG_ENDIAN,y)
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force, CFG_JR_INDEX,2)
$(call force, CFG_JR_INT,105)
$(call force, CFG_CAAM_SGT_ALIGN,4)
$(call force, CFG_CAAM_64BIT,y)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
$(call force, CFG_CAAM_ITR,n)
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1088ardb ls2088ardb ls1028ardb))
$(call force, CFG_CAAM_LITTLE_ENDIAN,y)
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force, CFG_JR_INDEX,2)
$(call force, CFG_JR_INT,174)
$(call force, CFG_NXP_CAAM_SGT_V2,y)
$(call force, CFG_CAAM_SGT_ALIGN,4)
$(call force, CFG_CAAM_64BIT,y)
$(call force, CFG_CAAM_ITR,n)
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),lx2160aqds lx2160ardb))
$(call force, CFG_CAAM_LITTLE_ENDIAN,y)
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force, CFG_JR_INDEX,2)
$(call force, CFG_JR_INT, 174)
$(call force, CFG_NB_JOBS_QUEUE, 80)
$(call force, CFG_NXP_CAAM_SGT_V2,y)
$(call force, CFG_CAAM_SGT_ALIGN,4)
$(call force, CFG_CAAM_64BIT,y)
$(call force, CFG_CAAM_ITR,n)
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8qm-flavorlist) $(mx8qx-flavorlist)))
$(call force, CFG_CAAM_SIZE_ALIGN,4)
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force, CFG_JR_INDEX,3)
$(call force, CFG_JR_INT,486)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8dxl-flavorlist)))
$(call force, CFG_CAAM_SIZE_ALIGN,4)
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force, CFG_JR_INDEX,3)
$(call force, CFG_JR_INT,356)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
$(call force, CFG_CAAM_JR_DISABLE_NODE,n)
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mm-flavorlist) $(mx8mn-flavorlist) \
	$(mx8mp-flavorlist) $(mx8mq-flavorlist)))
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,2)
$(call force, CFG_JR_INT,146)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
$(call force, CFG_JR_HAB_INDEX,0)
# There is a limitation on i.MX8M platforms regarding ECDSA Sign/Verify
# Size of Class 2 Context register is 40bytes, because of which sign/verify
# of a hash of more than 40bytes fails. So a workaround is implemented for
# this issue, controlled by CFG_NXP_CAAM_C2_CTX_REG_WA flag.
$(call force, CFG_NXP_CAAM_C2_CTX_REG_WA,y)
caam-drivers += MP DEK
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8ulp-flavorlist)))
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,2)
$(call force, CFG_JR_INT,114)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
$(call force, CFG_CAAM_ITR,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7ulp-flavorlist)))
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,0)
$(call force, CFG_JR_INT,137)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
$(call force, CFG_CAAM_ITR,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist) $(mx7d-flavorlist) \
	$(mx7s-flavorlist)))
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,0)
$(call force, CFG_JR_INT,137)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
caam-drivers += MP
caam-crypto-drivers += RSA DSA ECC DH MATH
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist) $(mx6qp-flavorlist) \
	$(mx6sx-flavorlist) $(mx6d-flavorlist) $(mx6dl-flavorlist) \
        $(mx6s-flavorlist) $(mx8ulp-flavorlist)))
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,0)
$(call force, CFG_JR_INT,137)
$(call force, CFG_NXP_CAAM_SGT_V1,y)
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

# Disable the i.MX CAAM driver
$(call force,CFG_IMX_CAAM,n,Mandated by CFG_NXP_CAAM)

# CAAM buffer alignment size
CFG_CAAM_SIZE_ALIGN ?= 1

# Default padding number for SGT allocation
CFG_CAAM_SGT_ALIGN ?= 1

# Enable job ring interruption
CFG_CAAM_ITR ?= y

# Keep the CFG_JR_INDEX as secure at runtime
CFG_NXP_CAAM_RUNTIME_JR ?= y

# Define the RSA Private Key Format used by the CAAM
#   Format #1: (n, d)
#   Format #2: (p, q, d)
#   Format #3: (p, q, dp, dq, qp)
CFG_NXP_CAAM_RSA_KEY_FORMAT ?= 3

# Disable device tree status of the secure job ring
CFG_CAAM_JR_DISABLE_NODE ?= y

# Define the default CAAM private key encryption generation and the bignum
# maximum size needed.
# CAAM_KEY_PLAIN_TEXT    -> 4096 bits
# CAAM_KEY_BLACK_ECB|CCM -> 4156 bits
CFG_CORE_BIGNUM_MAX_BITS ?= 4156

# Enable CAAM non-crypto drivers
$(foreach drv, $(caam-drivers), $(eval CFG_NXP_CAAM_$(drv)_DRV ?= y))

# Prefer CAAM HWRNG over PRNG seeded by CAAM
ifeq ($(CFG_NXP_CAAM_RNG_DRV), y)
CFG_WITH_SOFTWARE_PRNG ?= n
endif

# DEK driver requires the SM driver to be enabled
ifeq ($(CFG_NXP_CAAM_DEK_DRV), y)
$(call force, CFG_NXP_CAAM_SM_DRV,y,Mandated by CFG_NXP_CAAM_DEK_DRV)
endif

ifeq ($(CFG_CRYPTO_DRIVER), y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

# Enable CAAM Crypto drivers
$(foreach drv, $(caam-crypto-drivers), $(eval CFG_NXP_CAAM_$(drv)_DRV ?= y))

# Enable MAC crypto driver
ifeq ($(call cfg-one-enabled,CFG_NXP_CAAM_HMAC_DRV CFG_NXP_CAAM_CMAC_DRV),y)
$(call force, CFG_CRYPTO_DRV_MAC,y,Mandated by CFG_NXP_CAAM_HMAC/CMAC_DRV)
endif

# Enable CIPHER crypto driver
ifeq ($(CFG_NXP_CAAM_CIPHER_DRV), y)
$(call force, CFG_CRYPTO_DRV_CIPHER,y,Mandated by CFG_NXP_CAAM_CIPHER_DRV)
endif

# Enable HASH crypto driver
ifeq ($(CFG_NXP_CAAM_HASH_DRV), y)
$(call force, CFG_CRYPTO_DRV_HASH,y,Mandated by CFG_NXP_CAAM_HASH_DRV)
endif

# Enable RSA crypto driver
ifeq ($(CFG_NXP_CAAM_RSA_DRV), y)
$(call force, CFG_CRYPTO_DRV_RSA,y,Mandated by CFG_NXP_CAAM_RSA_DRV)
endif

# Enable ECC crypto driver
ifeq ($(CFG_NXP_CAAM_ECC_DRV), y)
$(call force, CFG_CRYPTO_DRV_ECC,y,Mandated by CFG_NXP_CAAM_ECC_DRV)
endif

# Enable DSA crypto driver
ifeq ($(CFG_NXP_CAAM_DSA_DRV), y)
$(call force, CFG_CRYPTO_DRV_DSA,y,Mandated by CFG_NXP_CAAM_DSA_DRV)
endif

# Enable DH crypto driver
ifeq ($(CFG_NXP_CAAM_DH_DRV), y)
$(call force, CFG_CRYPTO_DRV_DH,y,Mandated by CFG_NXP_CAAM_DH_DRV)
endif

# Enable ACIPHER crypto driver
ifeq ($(call cfg-one-enabled,CFG_CRYPTO_DRV_RSA CFG_CRYPTO_DRV_ECC \
	CFG_CRYPTO_DRV_DSA CFG_CRYPTO_DRV_DH),y)
$(call force, CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_CRYPTO_DRV_{RSA|ECC|DSA|DH})
endif

endif # CFG_CRYPTO_DRIVER
endif # CFG_NXP_CAAM
