ifeq ($(CFG_CRYPTO_WITH_CE),y)
srcs-$(CFG_ARM64_core) += ghash-ce-core_a64.S
srcs-$(CFG_ARM32_core) += ghash-ce-core_a32.S
srcs-y += aes-gcm-ce.c
endif

ifeq ($(CFG_CRYPTO_AES_ARM_CE),y)
srcs-y += aes_armv8a_ce.c
srcs-$(CFG_ARM64_core) += aes_modes_armv8a_ce_a64.S
aflags-aes_modes_armv8a_ce_a64.S-y += -DINTERLEAVE=4
srcs-$(CFG_ARM32_core) += aes_modes_armv8a_ce_a32.S
endif

ifeq ($(CFG_CRYPTO_SHA1_ARM_CE),y)
srcs-y += sha1_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sha1_armv8a_ce_a64.S
srcs-$(CFG_ARM32_core) += sha1_armv8a_ce_a32.S
endif

ifeq ($(CFG_CRYPTO_SHA256_ARM_CE),y)
srcs-y += sha256_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sha256_armv8a_ce_a64.S
srcs-$(CFG_ARM32_core) += sha256_armv8a_ce_a32.S
endif

ifeq ($(CFG_CRYPTO_SHA512_ARM_CE),y)
srcs-y += sha512_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sha512_armv8a_ce_a64.S
endif

ifeq ($(CFG_CRYPTO_SHA3_ARM_CE),y)
srcs-y += sha3_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sha3_armv8a_ce_a64.S
endif

ifeq ($(CFG_CRYPTO_SM3_ARM_CE),y)
srcs-y += sm3_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sm3_armv8a_ce_a64.S
endif

ifeq ($(CFG_CRYPTO_SM4_ARM_CE),y)
srcs-$(CFG_ARM64_core) += sm4_armv8a_ce.c
srcs-$(CFG_ARM64_core) += sm4_armv8a_ce_a64.S
else ifeq ($(CFG_CRYPTO_SM4_ARM_AESE),y)
srcs-$(CFG_ARM64_core) += sm4_armv8a_neon.c
srcs-$(CFG_ARM64_core) += sm4_armv8a_aese_a64.S
endif
