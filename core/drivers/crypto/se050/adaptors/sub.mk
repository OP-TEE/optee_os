cflags-y += -Wno-strict-aliasing
cflags-y += -DAX_EMBEDDED=1
cflags-y += -DVERBOSE_APDU_LOGS=0
cflags-y += -DT1oI2C_UM11225
cflags-y += -DT1oI2C
cflags-y += -DSSS_USE_FTR_FILE

incdirs-y += ./include

srcs-y += utils/scp_config.c
srcs-y += utils/utils.c
srcs-y += utils/info.c
srcs-y += apis/apdu.c
srcs-y += apis/user.c
srcs-y += apis/sss.c
