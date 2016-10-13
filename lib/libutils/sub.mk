subdirs-$(CFG_LIBUTILS_WITH_ISOC) += isoc
subdirs-y += ext

ifneq ($(sm),core) # User-mode
cflags-lib-$(CFG_U_LIBUTILS_GPROF) += -pg
endif
