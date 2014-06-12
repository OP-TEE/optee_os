global-incdirs-y += include


srcs-$(sm-core) += dlmalloc.c
cflags-remove-dlmalloc.c-y += -Wcast-align -Wstrict-aliasing=2

srcs-$(sm-core) += malloc_wrapper.c
cflags-malloc_wrapper.c-y += -Wno-redundant-decls

srcs-y += snprintf.c

srcs-y += stack_check.c
srcs-y += qsort.c
cflags-remove-qsort.c-y += -Wcast-align

srcs-y += strdup.c
srcs-y += strndup.c

subdirs-y += newlib
subdirs-$(arch_arm32) += arch/$(ARCH)
