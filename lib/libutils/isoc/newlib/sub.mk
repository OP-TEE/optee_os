incdirs-y := .

cflags-remove-y := -Wcast-align

srcs-y += memchr.c
cflags-memchr.c-y += -Wno-sign-compare

srcs-y += memcmp.c
srcs-y += memcpy.c
srcs-y += memmove.c

srcs-y += memset.c
cflags-memset.c-y += -Wno-sign-compare

srcs-y += strchr.c
srcs-y += strcmp.c

srcs-y += strcpy.c
cflags-strcpy.c-y += -Wno-parentheses

srcs-y += strlen.c
srcs-y += strncmp.c
srcs-y += strncpy.c
srcs-y += strnlen.c
srcs-y += strcat.c
srcs-y += strtoul.c
