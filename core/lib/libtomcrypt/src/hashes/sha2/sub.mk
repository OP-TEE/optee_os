srcs-$(CFG_CRYPTO_SHA224) += sha224.c

# SHA-224 needs SHA-256
SHA256 := $(call cfg-one-enabled, CFG_CRYPTO_SHA224 CFG_CRYPTO_SHA256)
ifeq ($(SHA256),y)
SHA256_CE := $(call cfg-one-enabled, CFG_CRYPTO_SHA256_ARM32_CE CFG_CRYPTO_SHA256_ARM64_CE)
ifeq ($(SHA256_CE),y)
srcs-y += sha256_armv8a_ce.c
srcs-$(CFG_CRYPTO_SHA256_ARM32_CE) += sha256_armv8a_ce_a32.S
srcs-$(CFG_CRYPTO_SHA256_ARM64_CE) += sha256_armv8a_ce_a64.S
else
srcs-y += sha256.c
endif
endif

srcs-$(CFG_CRYPTO_SHA384) += sha384.c
srcs-$(CFG_CRYPTO_SHA512) += sha512.c
srcs-$(CFG_CRYPTO_SHA512_256) += sha512_256.c
