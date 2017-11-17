ifeq ($(CFG_CRYPTO_WITH_CE),y)
srcs-$(CFG_ARM64_core) += ghash-ce-core_a64.S
srcs-$(CFG_ARM32_core) += ghash-ce-core_a32.S
srcs-y += aes-gcm-ce.c
endif
