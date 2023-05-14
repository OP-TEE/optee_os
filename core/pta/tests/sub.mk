srcs-$(call cfg-all-enabled,CFG_REE_FS CFG_WITH_USER_TA) += fs_htree.c
srcs-y += invoke.c
srcs-$(CFG_LOCKDEP) += lockdep.c
srcs-y += misc.c
cflags-misc.c-y += -fno-builtin
srcs-y += mutex.c
srcs-y += aes_perf.c
srcs-$(CFG_DT_DRIVER_EMBEDDED_TEST) += dt_driver_test.c
