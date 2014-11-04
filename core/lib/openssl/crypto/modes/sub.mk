incdirs-y := .. ../.. ../../include

cflags-remove-y := -Wcast-align

srcs-y += cbc128.c
srcs-y += ccm128.c
srcs-y += ctr128.c
srcs-y += gcm128.c
srcs-y += xts128.c
