core-platform-cflags += "-I${CFG_NXP_SE05X_PLUG_AND_TRUST}/optee_lib/include"
include core/drivers/crypto/se050/cflags.mk

incdirs-y += adaptors/include

subdirs-y += adaptors
subdirs-y += core

srcs-y += session.c
srcs-y += glue/i2c.c
srcs-y += glue/user.c
