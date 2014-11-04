incdirs-y := .. ../.. ../../include

cflags-remove-y := -pedantic -Wcast-align 
cflags-y += -Wno-unused-parameter -Wno-suggest-attribute=noreturn
cflags-y += -Wno-old-style-definition

srcs-y += conf_api.c
srcs-y += conf_def.c
srcs-y += conf_mod.c
srcs-y += conf_lib.c
