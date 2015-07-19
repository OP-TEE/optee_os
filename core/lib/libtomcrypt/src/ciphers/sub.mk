cflags-y += -Wno-unused-parameter

ifeq ($(CFG_CRYPTO_AES_ARM64_CE),y)
srcs-y += aes_arm64_ce.c
cflags-aes_arm64_ce.c-y += -march=armv8-a+crypto
srcs-y += aes_modes_arm64_ce_a64.S
aflags-aes_modes_arm64_ce_a64.S-y += -DINTERLEAVE=4
else
srcs-$(CFG_CRYPTO_AES) += aes.c
srcs-$(CFG_CRYPTO_AES) += aes_tab.c
endif

srcs-$(CFG_CRYPTO_DES) += des.c
