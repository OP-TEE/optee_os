cflags-y += -DAX_EMBEDDED=1
cflags-y += -DVERBOSE_APDU_LOGS=0
cflags-y += -DT1oI2C_UM1225_SE050
cflags-y += -DT1oI2C
cflags-y += -DSSS_USE_FTR_FILE

incdirs-y += ../adaptors/include
incdirs-y += include

srcs-y += scp03.c
srcs-y += storage.c
srcs-$(CFG_NXP_SE05X_RSA_DRV) += rsa.c
srcs-$(CFG_NXP_SE05X_CTR_DRV) += ctr.c
srcs-$(CFG_NXP_SE05X_HUK_DRV) += huk.c
srcs-$(CFG_NXP_SE05X_RNG_DRV) += rng.c
srcs-$(CFG_NXP_SE05X_CIPHER_DRV) += cipher.c
