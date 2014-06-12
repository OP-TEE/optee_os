
CC	= $(CROSS_COMPILE)gcc
LD	= $(CROSS_COMPILE)ld
AR	= $(CROSS_COMPILE)ar
NM	= $(CROSS_COMPILE)nm
OBJCOPY	= $(CROSS_COMPILE)objcopy
OBJDUMP	= $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

nostdinc	:= -nostdinc -isystem $(shell $(CC) -print-file-name=include \
			2> /dev/null)

# Get location of libgcc from gcc
libgcc  	:= $(shell $(CC) $(comp-cflags$(sm)) -print-libgcc-file-name \
			2> /dev/null)


