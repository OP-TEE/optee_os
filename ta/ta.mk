include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := $(ta-target)
sm-$(sm) := y

# Setup compiler for this sub module
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

#
# Config flags from mk/config.mk
#

ifeq ($(CFG_TA_MBEDTLS_SELF_TEST),y)
$(sm)-platform-cppflags += -DMBEDTLS_SELF_TEST
endif

ifeq ($(CFG_TEE_TA_MALLOC_DEBUG),y)
# Build malloc debug code into libutils: (mdbg_malloc(), mdbg_free(),
# mdbg_check(), etc.).
$(sm)-platform-cppflags += -DENABLE_MDBG=1
endif

# Config variables to be explicitly exported to the dev kit conf.mk
ta-mk-file-export-vars-$(sm) += CFG_TA_FLOAT_SUPPORT
ta-mk-file-export-vars-$(sm) += CFG_CACHE_API
ta-mk-file-export-vars-$(sm) += CFG_SECURE_DATA_PATH
ta-mk-file-export-vars-$(sm) += CFG_TA_MBEDTLS_SELF_TEST
ta-mk-file-export-vars-$(sm) += CFG_TA_MBEDTLS
ta-mk-file-export-vars-$(sm) += CFG_TA_MBEDTLS_MPI
ta-mk-file-export-vars-$(sm) += CFG_SYSTEM_PTA
ta-mk-file-export-vars-$(sm) += CFG_TA_DYNLINK
ta-mk-file-export-vars-$(sm) += CFG_TEE_TA_LOG_LEVEL

# Expand platform flags here as $(sm) will change if we have several TA
# targets. Platform flags should not change after inclusion of ta/ta.mk.
cppflags$(sm)	:= $(platform-cppflags) $($(sm)-platform-cppflags)
cflags$(sm)	:= $(platform-cflags) $($(sm)-platform-cflags)
aflags$(sm)	:= $(platform-aflags) $($(sm)-platform-aflags)

# Changes to cppflags$(sm) will only affect how TA dev kit libraries are
# compiled, these flags are not propagated to the TA
cppflags$(sm)	+= -include $(conf-file)
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

base-prefix := $(sm)-

libname = utils
libdir = lib/libutils
include mk/lib.mk

CFG_TA_MBEDTLS_MPI ?= y
ifeq ($(CFG_TA_MBEDTLS_MPI),y)
$(call force,CFG_TA_MBEDTLS,y)
else
libname = mpa
libdir = lib/libmpa
include mk/lib.mk
endif

libname = utee
libdir = lib/libutee
include mk/lib.mk

ifeq ($(CFG_TA_MBEDTLS),y)
libname = mbedtls
libdir = lib/libmbedtls
include mk/lib.mk
ta-mk-file-export-vars-$(sm) += CFG_TA_MBEDTLS
endif

base-prefix :=

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
	cp $$< $$@

cleanfiles += $2/$$(notdir $1)
ta_dev_kit: $2/$$(notdir $1)
ta_dev_kit-files += $2/$$(notdir $1)
endef

# Copy the .a files
$(foreach f, $(libfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/lib)))

# Copy .mk files
ta-mkfiles = mk/compile.mk mk/subdir.mk mk/gcc.mk mk/cleandirs.mk \
	ta/arch/$(ARCH)/link.mk ta/arch/$(ARCH)/link_shlib.mk \
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
ta-srcfiles = ta/arch/$(ARCH)/user_ta_header.c ta/arch/$(ARCH)/ta.ld.S
$(foreach f, $(ta-srcfiles), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/src)))

# Copy keys
ta-keys = keys/default_ta.pem
$(foreach f, $(ta-keys), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/keys)))

# Copy the scripts
ta-scripts = scripts/sign.py scripts/symbolize.py
$(foreach f, $(ta-scripts), \
	$(eval $(call copy-file, $(f), $(out-dir)/export-$(sm)/scripts)))

# Create config file
conf-mk-file-export := $(out-dir)/export-$(sm)/mk/conf.mk
sm-$(conf-mk-file-export) := $(sm)
define mk-file-export
.PHONY: $(conf-mk-file-export)
$(conf-mk-file-export):
	@$$(cmd-echo-silent) '  CHK    ' $$@
	$(q)echo sm := $$(sm-$(conf-mk-file-export)) > $$@.tmp
	$(q)echo sm-$$(sm-$(conf-mk-file-export)) := y >> $$@.tmp
	$(q)($$(foreach v, $$(ta-mk-file-export-vars-$$(sm-$(conf-mk-file-export))), \
		$$(if $$($$(v)),echo $$(v) := $$($$(v));,))) >> $$@.tmp
	$(q)echo '$$(ta-mk-file-export-add-$$(sm-$(conf-mk-file-export)))' | sed 's/_nl_ */\n/g' >> $$@.tmp
	$(q)$(call mv-if-changed,$$@.tmp,$$@)
endef
$(eval $(mk-file-export))

cleanfiles := $(cleanfiles) $(conf-mk-file-export)
ta_dev_kit: $(conf-mk-file-export)

all: ta_dev_kit
