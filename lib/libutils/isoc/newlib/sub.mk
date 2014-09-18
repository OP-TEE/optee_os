srcs-y += memchr.c
cflags-remove-memchr.c-y += -Wcast-align
cflags-memchr.c-y += -Wno-sign-compare

srcs-y += memcmp.c
cflags-remove-memcmp.c-y += -Wcast-align

srcs-y += memcpy.c
cflags-remove-memcpy.c-y += -Wcast-align

srcs-y += memmove.c
cflags-remove-memmove.c-y += -Wcast-align

srcs-y += memset.c
cflags-remove-memset.c-y += -Wcast-align
cflags-memset.c-y += -Wno-sign-compare

srcs-y += strcmp.c
cflags-remove-strcmp.c-y += -Wcast-align

srcs-y += strlen.c
cflags-remove-strlen.c-y += -Wcast-align

srcs-y += strnlen.c
