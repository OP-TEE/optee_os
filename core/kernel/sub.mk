srcs-y += assert.c
srcs-y += tee_dispatch.c
srcs-y += tee_misc.c
srcs-y += panic.c
srcs-y += handle.c
srcs-$(CFG_DT) += console_dt.c
srcs-$(CFG_DT) += dt.c
