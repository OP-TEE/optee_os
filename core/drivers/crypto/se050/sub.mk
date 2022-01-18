include ${CFG_NXP_SE05X_PLUG_AND_TRUST}/cflags.mk

incdirs_ext-y += ${CFG_NXP_SE05X_PLUG_AND_TRUST}/optee_lib/include
incdirs-y += adaptors/include

subdirs-y += adaptors
subdirs-y += core
subdirs_ext-y += ${CFG_NXP_SE05X_PLUG_AND_TRUST}

srcs-y += session.c
srcs-y += glue/i2c.c
srcs-y += glue/user.c
