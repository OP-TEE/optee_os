global-incdirs-y += .
srcs-y += adler32.c
srcs-y += inffast.c
srcs-y += inflate.c
srcs-y += inftrees.c
srcs-y += zutil.c
cflags-remove-y += -Wold-style-definition
cflags-remove-y += -Wswitch-default
