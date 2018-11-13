global-incdirs-y += include
cflags-y += -Wno-cast-align
cflags-y += -Wno-sign-compare
cflags-y += -Wno-switch-default
srcs-y += fdt.c fdt_ro.c fdt_wip.c fdt_sw.c fdt_rw.c fdt_strerror.c
srcs-y += fdt_empty_tree.c fdt_addresses.c fdt_overlay.c
