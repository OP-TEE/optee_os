global-incdirs-y += include

cflags-y += -Wno-old-style-definition
cflags-y += -Wno-switch-default
cflags-y += -Wno-strict-prototypes
cflags-y += -Wno-missing-prototypes
cflags-y += -Wno-missing-declarations
cflags-y += -Wno-shift-negative-value

srcs-y += adler32.c
srcs-y += crc32.c
srcs-y += deflate.c
srcs-y += infback.c
srcs-y += inffast.c
srcs-y += inflate.c
srcs-y += inftrees.c
srcs-y += trees.c
srcs-y += uncompr.c
srcs-y += zutil.c
