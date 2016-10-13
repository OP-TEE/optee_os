subdirs-$(CFG_LIBUTILS_WITH_ISOC) += isoc
subdirs-y += ext

ifneq ($(sm),core) # User-mode
cflags-lib-$(CFG_ULIBS_GPROF) += -pg
endif
