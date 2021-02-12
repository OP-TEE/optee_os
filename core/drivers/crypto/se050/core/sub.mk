include core/drivers/crypto/se050/cflags.mk

incdirs-y += ../adaptors/include
incdirs-y += include

srcs-y += scp03.c
srcs-y += storage.c
srcs-$(CFG_NXP_SE05X_RSA_DRV) += rsa.c
srcs-$(CFG_NXP_SE05X_ECC_DRV) += ecc.c
srcs-$(CFG_NXP_SE05X_CTR_DRV) += ctr.c
srcs-$(CFG_NXP_SE05X_HUK_DRV) += huk.c
srcs-$(CFG_NXP_SE05X_RNG_DRV) += rng.c
srcs-$(CFG_NXP_SE05X_CIPHER_DRV) += cipher.c
