cflags-y += -Wno-strict-aliasing
include core/drivers/crypto/se050/cflags.mk

incdirs-y += ./include

srcs-y += utils/scp_config.c
srcs-y += utils/utils.c
srcs-y += utils/info.c
srcs-y += apis/apdu.c
srcs-y += apis/user.c
srcs-y += apis/sss.c
