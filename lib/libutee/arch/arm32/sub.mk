cppflags-y += -I$(sub-dir)/../..

srcs-y += bget_malloc.c
cflags-remove-bget_malloc.c-y += -Wold-style-definition -Wredundant-decls
cflags-bget_malloc.c-y += -Wno-sign-compare -Wno-cast-align

srcs-y += user_ta_entry.c
srcs-y += utee_misc.c
srcs-y += utee_syscalls_asm.S
