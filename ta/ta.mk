include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := user_ta
sm-$(sm) := y

# Setup compiler for this sub module
CROSS_COMPILE_$(sm)	?= $(CROSS_COMPILE)
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

include ta/arch/$(ARCH)/$(ARCH).mk

cppflags$(sm)	+= $(platform-cppflags) $(user_ta-platform-cppflags)
cflags$(sm)	+= $(platform-cflags) $(user_ta-platform-cflags)
aflags$(sm)	+= $(platform-aflags) $(user_ta-platform-aflags)

# Config flags from mk/config.mk
cppflags$(sm) += -DCFG_TRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
cppflags$(sm) += -DCFG_TEE_CORE_USER_MEM_DEBUG=$(CFG_TEE_CORE_USER_MEM_DEBUG)


base-prefix := $(sm)-

libname = utils
libdir = lib/libutils
include mk/lib.mk

libname = mpa
libdir = lib/libmpa
include mk/lib.mk

libname = utee
libdir = lib/libutee
include mk/lib.mk

base-prefix :=

incdirs-host := $(filter-out lib/libutils%, $(incdirs$(sm)))
incfiles-extra-host := lib/libutils/ext/include/compiler.h
incfiles-extra-host += lib/libutils/ext/include/util.h

#
# Copy lib files and exported headers from each lib
#

define copy-file
$2/$$(notdir $1): $1
	@set -e; \
	mkdir -p $$(dir $$@) ; \
	echo '  INSTALL $$@' ; \
	cp $$< $$@

cleanfiles += $2/$$(notdir $1)
all: $2/$$(notdir $1)
endef

# Copy the .a files
$(foreach f, $(libfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-user_ta/lib)))

# Copy .mk files
ta-mkfiles = mk/compile.mk mk/subdir.mk mk/gcc.mk \
	$(wildcard core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk) \
	$(wildcard ta/arch/$(ARCH)/link.mk) \
	ta/mk/ta_dev_kit.mk

$(foreach f, $(ta-mkfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-user_ta/mk)))

# Special treatment for ta/arch/$(ARCH)/$(ARCH).mk
arch-arch-mk := $(out-dir)/export-user_ta/mk/arch.mk
$(arch-arch-mk): ta/arch/$(ARCH)/$(ARCH).mk
	@set -e; \
	mkdir -p $(dir $@) ; \
	echo '  INSTALL $@' ; \
	cp $< $@

cleanfiles += $(arch-arch-mk)
all: $(arch-arch-mk)

# Copy the .h files for TAs
define copy-incdir
sf := $(subst $1/, , $(shell find $1 -name "*.h"))
$$(foreach h, $$(sf), $$(eval $$(call copy-file, $1/$$(h), \
	$$(patsubst %/,%,$$(subst /./,/,$2/$$(dir $$(h)))))))
endef
$(foreach d, $(incdirs$(sm)), \
	$(eval $(call copy-incdir, $(d), $(out-dir)/export-user_ta/include)))

# Copy the .h files needed by host
$(foreach d, $(incdirs-host), \
	$(eval $(call copy-incdir, $(d), $(out-dir)/export-user_ta/host_include)))
$(foreach f, $(incfiles-extra-host), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-user_ta/host_include)))

# Copy the src files
ta-srcfiles = ta/arch/$(ARCH)/user_ta_header.c \
	$(wildcard ta/arch/$(ARCH)/user_ta_elf_arm.lds)
$(foreach f, $(ta-srcfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-user_ta/src)))

# Copy the scripts
ta-scripts = $(wildcard ta/arch/$(ARCH)/fix_ta_binary)
$(foreach f, $(ta-scripts), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-user_ta/scripts)))
