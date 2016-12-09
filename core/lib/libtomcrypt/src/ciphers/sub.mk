cflags-y += -Wno-unused-parameter

ifeq ($(CFG_CRYPTO_AES_ARM64_CE),y)
srcs-y += aes_armv8a_ce.c
cflags-aes_armv8a_ce.c-y += -march=armv8-a+crypto
srcs-y += aes_modes_armv8a_ce_a64.S
aflags-aes_modes_armv8a_ce_a64.S-y += -DINTERLEAVE=4
else
ifeq ($(CFG_CRYPTO_AES_ARM32_CE),y)
srcs-y += aes_armv8a_ce.c
srcs-y += aes_modes_armv8a_ce_a32.S
else
srcs-$(CFG_CRYPTO_AES) += aes.c
endif
endif

srcs-$(CFG_CRYPTO_DES) += des.c
