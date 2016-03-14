global-incdirs-y += .

srcs-y += fdt_addresses.c fdt.c fdt_empty_tree.c fdt_ro.c fdt_rw.c fdt_strerror.c fdt_sw.c fdt_wip.c

cflags-remove-y += -Wcast-align

cflags-fdt.c-y += -Wno-sign-compare -Wno-switch-default
cflags-fdt_ro.c-y += -Wno-sign-compare -Wno-switch-default
cflags-fdt_strerror.c-y += -Wno-sign-compare
cflags-fdt_sw.c-y += -Wno-sign-compare
