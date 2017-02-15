include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := $(ta-target)
sm-$(sm) := y

# Setup compiler for this sub module
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

# Expand platform flags here as $(sm) will change if we have several TA
# targets. Platform flags should not change after inclusion of ta/ta.mk.
cppflags$(sm)	:= $(platform-cppflags) $($(sm)-platform-cppflags)
cflags$(sm)	:= $(platform-cflags) $($(sm)-platform-cflags)
aflags$(sm)	:= $(platform-aflags) $($(sm)-platform-aflags)

cppflags$(sm)	+= -include $(conf-file)

# Config flags from mk/config.mk
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
ifeq ($(CFG_TEE_TA_MALLOC_DEBUG),y)
cppflags$(sm) += -DENABLE_MDBG=1
endif

base-prefix := $(sm)-

libname = utils
libdir = lib/libutils
include mk/lib.mk

libname = zlib
libdir = lib/libzlib
include mk/lib.mk

libname = png
libdir = lib/libpng
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
incfiles-extra-host += lib/libutils/ext/include/types_ext.h
incfiles-extra-host += $(conf-file)
incfiles-extra-host += $(conf-mk-file)
incfiles-extra-host += core/include/tee/tee_fs_key_manager.h
incfiles-extra-host += core/include/tee/fs_htree.h
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
ta-mkfiles = mk/compile.mk mk/subdir.mk mk/gcc.mk mk/cleandirs.mk \
	$(wildcard ta/arch/$(ARCH)/link.mk) \
	ta/mk/ta_dev_kit.mk

$(foreach f, $(ta-mkfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/mk)))

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
conf-mk-file-export := $(out-dir)/export-$(sm)/mk/conf.mk
sm-$(conf-mk-file-export) := $(sm)
define mk-file-export
$(conf-mk-file-export): $(conf-mk-file)
	@$$(cmd-echo-silent) '  GEN    ' $$@
	$(q)echo sm := $$(sm-$(conf-mk-file-export)) > $$@
	$(q)echo sm-$$(sm-$(conf-mk-file-export)) := y >> $$@
	$(q)echo CFG_TA_FLOAT_SUPPORT := $$(CFG_TA_FLOAT_SUPPORT) >> $$@
	$(q)($$(foreach v, $$(ta-mk-file-export-vars-$$(sm-$(conf-mk-file-export))), \
		echo $$(v) := $$($$(v));)) >> $$@
	$(q)echo '$$(ta-mk-file-export-add-$$(sm-$(conf-mk-file-export)))' | sed 's/_nl_ */\n/g' >> $$@
endef
$(eval $(mk-file-export))

cleanfiles := $(cleanfiles) $(conf-mk-file-export)
all: $(conf-mk-file-export)
