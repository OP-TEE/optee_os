cflags-y += -Wno-strict-aliasing
include ${CFG_NXP_SE05X_PLUG_AND_TRUST}/cflags.mk

incdirs_ext-y += ${CFG_NXP_SE05X_PLUG_AND_TRUST}/optee_lib/include
incdirs-y += ./include

srcs-y += utils/scp_config.c
srcs-y += utils/utils.c
srcs-y += utils/info.c
srcs-y += apis/apdu.c
srcs-y += apis/user.c
srcs-y += apis/sss.c
