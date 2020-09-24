core-platform-cflags += "-I${CFG_NXP_SE05X_PLUG_AND_TRUST}/optee_lib/include"

cflags-y += -DAX_EMBEDDED=1
cflags-y += -DVERBOSE_APDU_LOGS=0
cflags-y += -DT1oI2C_UM11225
cflags-y += -DT1oI2C
cflags-y += -DSSS_USE_FTR_FILE

incdirs-y += adaptors/include

subdirs-y += adaptors
subdirs-y += core

srcs-y += session.c
srcs-y += glue/i2c.c
srcs-y += glue/user.c
