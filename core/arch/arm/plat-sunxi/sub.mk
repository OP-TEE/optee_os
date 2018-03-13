global-incdirs-y += .
srcs-y += main.c
srcs-y += plat_init.S
srcs-y += psci.c
cflags-psci.c-y += -Wno-suggest-attribute=noreturn
