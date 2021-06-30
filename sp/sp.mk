include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := $(sp-target)
sm-$(sm) := y

# Setup compiler for this sub module
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

#
# Config flags from mk/config.mk
#

# Config variables to be explicitly exported to the dev kit conf.mk
sp-mk-file-export-add-$(sm) += CFG_TEE_SP_LOG_LEVEL ?= $(CFG_TEE_SP_LOG_LEVEL)_nl_

# Expand platform flags here as $(sm) will change if we have several SP
# targets. Platform flags should not change after inclusion of sp/sp.mk.
cppflags$(sm)	:= $(platform-cppflags) $($(sm)-platform-cppflags)
cflags$(sm)	:= $(platform-cflags) $($(sm)-platform-cflags)
aflags$(sm)	:= $(platform-aflags) $($(sm)-platform-aflags)

# Changes to cppflags$(sm) will only affect how SP dev kit libraries are
# compiled, these flags are not propagated to the SP
cppflags$(sm)	+= -include $(conf-file)
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_SP_LOG_LEVEL)

base-prefix := $(sm)-

libname = utils
libdir = lib/libutils
libuuid = 71855bba-6055-4293-a63f-b0963a737360
include mk/lib.mk

base-prefix :=

incdirs$(sm) += sp/include

incdirs-host := $(filter-out lib/libutils%, $(incdirs$(sm)))
incfiles-extra-host := lib/libutils/ext/include/compiler.h
incfiles-extra-host += lib/libutils/ext/include/util.h
incfiles-extra-host += lib/libutils/ext/include/types_ext.h
incfiles-extra-host += $(conf-file)
incfiles-extra-host += $(conf-mk-file)
incfiles-extra-host += $(conf-cmake-file)
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
	cp -P $$< $$@

cleanfiles += $2/$$(notdir $1)
sp_dev_kit: $2/$$(notdir $1)
sp_dev_kit-files += $2/$$(notdir $1)
sp_dev_kit-files-$3 += $2/$$(notdir $1)
endef

# Copy the .a files
$(foreach f, $(libfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/lib,lib)))

# Copy .mk files
sp-mkfiles = mk/compile.mk mk/subdir.mk mk/gcc.mk mk/clang.mk mk/cleandirs.mk \
	mk/cc-option.mk \
	sp/arch/$(ARCH)/link.mk \
	sp/mk/sp_dev_kit.mk

$(foreach f, $(sp-mkfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/mk)))

# Copy the .h files for SPs
define copy-incdir
sf := $(subst $1/, , $(shell find $1 -name "*.[hS]"))
$$(foreach h, $$(sf), $$(eval $$(call copy-file, $1/$$(h), \
	$$(patsubst %/,%,$$(subst /./,/,$2/$$(dir $$(h)))),$3)))
endef
$(foreach d, $(incdirs$(sm)), \
	$(eval $(call copy-incdir,$(d),$(out-dir)/export-$(sm)/include,include)))

# Copy the .h files needed by host
$(foreach d, $(incdirs-host), \
	$(eval $(call copy-incdir, $(d), $(out-dir)/export-$(sm)/host_include)))
$(foreach f, $(incfiles-extra-host), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/host_include)))

# Copy the src files
sp-srcfiles = sp/arch/$(ARCH)/sp_assert.c
sp-srcfiles += sp/arch/$(ARCH)/sp_header.c
sp-srcfiles += sp/arch/$(ARCH)/sp_entry.c
sp-srcfiles += sp/arch/$(ARCH)/sp_trace.c
sp-srcfiles += sp/arch/$(ARCH)/sp.ld.S
ifeq ($(sp-target),sp_arm32)
sp-srcfiles += sp/arch/$(ARCH)/sp_entry_a32.S
endif
$(foreach f, $(sp-srcfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/src)))

# Copy keys
sp-keys = keys/default_sp.pem
$(foreach f, $(sp-keys), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/keys)))

# Copy the scripts
sp-scripts = scripts/sign_encrypt.py scripts/symbolize.py
$(foreach f, $(sp-scripts), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/scripts)))

# Create config file
conf-mk-file-export := $(out-dir)/export-$(sm)/mk/conf.mk
sm-$(conf-mk-file-export) := $(sm)
define mk-file-export
.PHONY: $(conf-mk-file-export)
$(conf-mk-file-export):
	@$$(cmd-echo-silent) '  CHK    ' $$@
	$(q)mkdir -p $$(dir $$@)
	$(q)echo sm := $$(sm-$(conf-mk-file-export)) > $$@.tmp
	$(q)echo sm-$$(sm-$(conf-mk-file-export)) := y >> $$@.tmp
	$(q)($$(foreach v, $$(sp-mk-file-export-vars-$$(sm-$(conf-mk-file-export))), \
		$$(if $$($$(v)),echo $$(v) := $$($$(v));,))) >> $$@.tmp
	$(q)echo '$$(sp-mk-file-export-add-$$(sm-$(conf-mk-file-export)))' | sed 's/_nl_ */\n/g' >> $$@.tmp
	$(q)$(call mv-if-changed,$$@.tmp,$$@)
endef
$(eval $(mk-file-export))

cleanfiles := $(cleanfiles) $(conf-mk-file-export)
sp_dev_kit: $(conf-mk-file-export)

all: sp_dev_kit
