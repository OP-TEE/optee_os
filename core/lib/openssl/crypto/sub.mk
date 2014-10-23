incdirs-y := . .. ../include

cflags-remove-y := -Wredundant-decls
cflags-y := -Wno-unused-parameter -Wno-nested-externs -Wno-suggest-attribute=noreturn

srcs-y += cryptlib.c
srcs-y += mem.c
srcs-y += mem_clr.c
srcs-y += o_init.c

subdirs-y += asn1
subdirs-y += aes
subdirs-y += bn
subdirs-y += buffer
subdirs-y += des
subdirs-y += dh
subdirs-y += dsa
subdirs-y += err
subdirs-y += evp
subdirs-y += lhash
subdirs-y += md5
subdirs-y += modes
subdirs-y += objects
subdirs-y += rand
subdirs-y += rsa
subdirs-y += sha
subdirs-y += stack
