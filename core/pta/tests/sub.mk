srcs-$(CFG_WITH_USER_TA) += fs_htree.c
srcs-y += interrupt.c
srcs-y += invoke.c
srcs-$(CFG_LOCKDEP) += lockdep.c
srcs-y += misc.c
cflags-misc.c-y += -fno-builtin
srcs-y += mutex.c
srcs-y += aes_perf.c
