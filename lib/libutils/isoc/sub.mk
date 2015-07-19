global-incdirs-y += include

srcs-y += bget_malloc.c
cflags-remove-bget_malloc.c-y += -Wold-style-definition -Wredundant-decls
cflags-bget_malloc.c-y += -Wno-sign-compare -Wno-cast-align

srcs-y += snprintf.c

srcs-y += stack_check.c
srcs-y += qsort.c
cflags-qsort.c-y += -Wno-inline
cflags-remove-qsort.c-y += -Wcast-align

srcs-y += strdup.c
srcs-y += strndup.c

subdirs-y += newlib
subdirs-$(arch_arm) += arch/$(ARCH)
