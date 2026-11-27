
CC$(sm)		:= $(CROSS_COMPILE_$(sm))gcc
CXX$(sm)	:= $(CROSS_COMPILE_$(sm))g++
CPP$(sm)	:= $(CROSS_COMPILE_$(sm))cpp
LD$(sm)		:= $(CROSS_COMPILE_$(sm))ld.bfd
AR$(sm)		:= $(CROSS_COMPILE_$(sm))ar
NM$(sm)		:= $(CROSS_COMPILE_$(sm))nm
OBJCOPY$(sm)	:= $(CROSS_COMPILE_$(sm))objcopy
OBJDUMP$(sm)	:= $(CROSS_COMPILE_$(sm))objdump
READELF$(sm)	:= $(CROSS_COMPILE_$(sm))readelf

nostdinc$(sm)	:= -nostdinc -isystem $(shell $(CC$(sm)) \
			-print-file-name=include 2> /dev/null)

# Get location of libgcc from gcc
define _gcc_set_libs
libgcc$1  	= $$(shell $$(CC$1) $$(CFLAGS$$(arch-bits-$1)) \
			$$(filter -m%,$$(cflags$1)) \
			-print-libgcc-file-name 2> /dev/null)
libstdc++$1	= $$(shell $$(CXX$1) $$(CXXFLAGS$$(arch-bits-$1)) \
			$$(filter -m%,$$(cxxflags$1)) $$(comp-cxxflags$1) \
			-print-file-name=libstdc++.a 2> /dev/null)
libgcc_eh$1	= $$(shell $$(CXX$1) $$(CXXFLAGS$$(arch-bits-$1)) \
			$$(filter -m%,$$(cxxflags$1)) $$(comp-cxxflags$1) \
			-print-file-name=libgcc_eh.a 2> /dev/null)
endef
$(eval $(call _gcc_set_libs,$(sm)))

# Define these to something to discover accidental use
CC		:= false
CXX		:= false
CPP		:= false
LD		:= false
AR		:= false
NM		:= false
OBJCOPY		:= false
OBJDUMP		:= false
READELF		:= false
nostdinc	:= --bad-nostdinc-variable
libgcc  	:= --bad-libgcc-variable


