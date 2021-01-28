global-incdirs-y += include

srcs-y += bget_malloc.c
cflags-remove-bget_malloc.c-y += -Wold-style-definition -Wredundant-decls
cflags-bget_malloc.c-y += -Wno-sign-compare -Wno-cast-align
ifeq ($(sm),core)
cflags-remove-bget_malloc.c-y += $(cflags_kasan)
endif
srcs-y += isdigit.c
srcs-y += isxdigit.c
srcs-y += qsort.c
cflags-qsort.c-y += -Wno-inline
cflags-remove-qsort.c-y += -Wcast-align
srcs-y += sprintf.c
srcs-y += snprintf.c
srcs-y += stack_check.c
srcs-y += strdup.c
srcs-y += strndup.c
srcs-y += tolower.c
srcs-y += isalpha.c
srcs-y += isspace.c
srcs-y += isupper.c
srcs-y += isalnum.c
srcs-y += iscntrl.c
srcs-y += isgraph.c
srcs-y += islower.c
srcs-y += isprint.c
srcs-y += ispunct.c
srcs-y += toupper.c

ifneq (,$(filter ta_%,$(sm)))
srcs-y += fp.c
srcs-y += fputc.c
srcs-y += fputs.c
srcs-y += fwrite.c
srcs-y += write.c
endif

subdirs-y += newlib
subdirs-y += arch/$(ARCH)
