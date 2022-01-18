include ${CFG_NXP_SE05X_PLUG_AND_TRUST}/cflags.mk

incdirs_ext-y += ${CFG_NXP_SE05X_PLUG_AND_TRUST}/optee_lib/include
incdirs-y += ../adaptors/include
incdirs-y += include

srcs-y += storage.c
srcs-$(CFG_NXP_SE05X_RSA_DRV) += rsa.c
srcs-$(CFG_NXP_SE05X_ECC_DRV) += ecc.c
srcs-$(CFG_NXP_SE05X_CTR_DRV) += ctr.c
srcs-$(CFG_NXP_SE05X_DIEID_DRV) += die_id.c
srcs-$(CFG_NXP_SE05X_RNG_DRV) += rng.c
srcs-$(CFG_NXP_SE05X_CIPHER_DRV) += cipher.c
srcs-$(CFG_NXP_SE05X_SCP03_DRV) += scp03.c
srcs-$(CFG_NXP_SE05X_APDU_DRV) += apdu.c
