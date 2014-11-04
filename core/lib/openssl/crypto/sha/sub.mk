incdirs-y := .. ../.. ../../include

cflags-remove-y := -Wcast-align

srcs-y += sha1_one.c
srcs-y += sha1dgst.c
srcs-y += sha256.c
srcs-y += sha512.c
