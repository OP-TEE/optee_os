global-incdirs-y += include

# Disable eventual ARM NEON optimization
cppflags-y += -DPNG_ARM_NEON_OPT=0

cflags-y += -Wno-extra

srcs-y += png.c
srcs-y += pngerror.c
srcs-y += pngget.c
srcs-y += pngmem.c
srcs-y += pngpread.c
srcs-y += pngread.c
srcs-y += pngrio.c
srcs-y += pngrtran.c
srcs-y += pngrutil.c
srcs-y += pngset.c
srcs-y += pngtrans.c
srcs-y += pngwio.c
srcs-y += pngwrite.c
srcs-y += pngwtran.c
srcs-y += pngwutil.c
