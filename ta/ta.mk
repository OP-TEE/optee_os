include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := $(ta-target)
sm-$(sm) := y

# Setup compiler for this sub module
CROSS_COMPILE_$(sm)	?= $(CROSS_COMPILE)
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

include ta/arch/$(ARCH)/$(ARCH).mk

# Expand platform flags here as $(sm) will change if we have several TA
# targets. Platform flags should not change after inclusion of ta/ta.mk.
cppflags$(sm)	:= $(platform-cppflags) $($(sm)-platform-cppflags)
cflags$(sm)	:= $(platform-cflags) $($(sm)-platform-cflags)
aflags$(sm)	:= $(platform-aflags) $($(sm)-platform-aflags)

# Config flags from mk/config.mk
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
cppflags$(sm) += -DCFG_TEE_CORE_USER_MEM_DEBUG=$(CFG_TEE_CORE_USER_MEM_DEBUG)
ifeq ($(CFG_TEE_TA_MALLOC_DEBUG),y)
cppflags$(sm) += -DENABLE_MDBG=1
endif
ifeq ($(CFG_TEE_PANIC_DEBUG),y)
cppflags$(sm) += -DCFG_TEE_PANIC_DEBUG=1
endif

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
incfiles-extra-host += $(out-dir)/core/include/generated/conf.h
incfiles-extra-host += $(out-dir)/core/conf.mk
incfiles-extra-host += core/include/tee/tee_fs_key_manager.h
incfiles-extra-host += core/include/signed_hdr.h

#
# Copy lib files and exported headers from each lib
#

define copy-file
$2/$$(notdir $1): $1
	@set -e; \
	mkdir -p $$(dir $$@) ; \
	$(cmd-echo-silent) '  INSTALL $$@' ; \
	cp $$< $$@

cleanfiles += $2/$$(notdir $1)
all: $2/$$(notdir $1)
endef

# Copy the .a files
$(foreach f, $(libfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/lib)))

# Copy .mk files
ta-mkfiles = mk/compile.mk mk/subdir.mk mk/gcc.mk \
	$(wildcard core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk) \
	$(wildcard ta/arch/$(ARCH)/link.mk) \
	ta/mk/ta_dev_kit.mk

$(foreach f, $(ta-mkfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/mk)))

# Special treatment for ta/arch/$(ARCH)/$(ARCH).mk
arch-arch-mk := $(out-dir)/export-$(sm)/mk/arch.mk
$(arch-arch-mk): ta/arch/$(ARCH)/$(ARCH).mk
	@set -e; \
	mkdir -p $(dir $@) ; \
	$(cmd-echo-silent) '  INSTALL $@' ; \
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
	$(eval $(call copy-incdir, $(d), $(out-dir)/export-$(sm)/include)))

# Copy the .h files needed by host
$(foreach d, $(incdirs-host), \
	$(eval $(call copy-incdir, $(d), $(out-dir)/export-$(sm)/host_include)))
$(foreach f, $(incfiles-extra-host), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/host_include)))

# Copy the src files
ta-srcfiles = ta/arch/$(ARCH)/user_ta_header.c \
	$(wildcard ta/arch/$(ARCH)/ta.ld.S)
$(foreach f, $(ta-srcfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/src)))

# Copy keys
ta-keys = keys/default_ta.pem
$(foreach f, $(ta-keys), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/keys)))

# Copy the scripts
ta-scripts = $(wildcard scripts/sign.py)
$(foreach f, $(ta-scripts), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/scripts)))

# Create config file
conf-file := $(out-dir)/export-$(sm)/mk/conf.mk
sm-$(conf-file) := $(sm)
$(conf-file): $(conf-mk-file)
	@$(cmd-echo-silent) '  GEN    ' $@
	$(q)echo sm := $(sm-$(@)) > $@
	$(q)echo sm-$(sm-$(@)) := y >> $@
	$(q)echo CFG_ARM32_$(sm-$(@)) := $(CFG_ARM32_$(sm-$(@))) >> $@
	$(q)echo CFG_ARM64_$(sm-$(@)) := $(CFG_ARM64_$(sm-$(@))) >> $@
	$(q)echo CFG_TA_FLOAT_SUPPORT := $(CFG_TA_FLOAT_SUPPORT) >> $@

cleanfiles := $(cleanfiles) $(conf-file)
all: $(conf-file)
