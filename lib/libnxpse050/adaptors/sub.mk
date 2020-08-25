cflags-y += -Wno-error
cflags-y += -Wno-implicit-function-declaration

cflags-y += -DAX_EMBEDDED=1
cflags-y += -DVERBOSE_APDU_LOGS=0
cflags-y += -DT1oI2C_UM11225
cflags-y += -DT1oI2C
cflags-y += -DSSS_USE_FTR_FILE

incdirs-y += ./include
incdirs-y += ../se050/glue/include
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/inc/
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/libCommon/infra/
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/libCommon/smCom/
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/libCommon/smCom/T1oI2C/
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/platform/inc/
incdirs-y += ../se050/plug-and-trust/hostlib/hostLib/se05x_03_xx_xx/
incdirs-y += ../se050/plug-and-trust/sss/inc/
incdirs-y += ../se050/plug-and-trust/sss/port/default/
incdirs-y += ../se050/plug-and-trust/sss/src/user/crypto/

# called by the core library
srcs-y += utils/scp_config.c
srcs-y += utils/context.c
srcs-y += utils/utils.c
srcs-y += utils/info.c
srcs-y += apis/apdu.c
srcs-y += apis/user.c
srcs-y += apis/sss.c
