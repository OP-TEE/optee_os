# Input
#
# libname	the name of the lib
# libdir	directory of lib which also is used as input to
#		mk/subdir.mk
# conf-file     [optional] if set, all objects will depend on $(conf-file)
# [if CFG_ULIBS_SHARED==y]
#   libuuid	the UUID of the shared lib
#   libl	other libraries this library depends on; used to generate the
#               proper link arguments (-Lxxx -lyyy) and to add dependencies
#               on the needed .so files
# [endif]
#
# Output
#
# updated cleanfiles and
# updated libfiles, libdirs, libnames and libdeps


subdirs = $(libdir)
include mk/subdir.mk
ifeq ($(filter $(sm), core ldelf),) # TA
ifeq ($(CFG_ULIBS_MCOUNT),y)
cflags-lib$(libname)-$(sm) += -pg
endif
endif
include mk/compile.mk

lib-libfile	:= $(out-dir)/$(base-prefix)$(libdir)/lib$(libname).a
ifeq ($(CFG_ULIBS_SHARED),y)
lib-shlibfile	:= $(out-dir)/$(base-prefix)$(libdir)/lib$(libname).so
lib-shlibstrippedfile := $(out-dir)/$(base-prefix)$(libdir)/lib$(libname).stripped.so
lib-shlibtafile	:= $(out-dir)/$(base-prefix)$(libdir)/$(libuuid).ta
lib-libuuidln	:= $(out-dir)/$(base-prefix)$(libdir)/$(libuuid).elf
lib-shlibfile-$(libname)-$(sm) := $(lib-shlibfile)
lib-libdir-$(libname)-$(sm) := $(out-dir)/$(base-prefix)$(libdir)
lib-needed-so-files := $(foreach l,$(libl),$(lib-shlibfile-$(l)-$(sm)))
lib-Ll-args := $(foreach l,$(libl),-L$(lib-libdir-$(l)-$(sm)) -l$(l))
endif
cleanfiles	:= $(lib-libfile) $(lib-shlibfile) $(lib-shlibstrippedfile) $(lib-shlibtafile) $(lib-libuuidln) $(cleanfiles)
libfiles	:= $(lib-libfile) $(lib-shlibfile) $(lib-shlibstrippedfile) $(lib-shlibtafile) $(lib-libuuidln) $(libfiles)
libdirs 	:= $(out-dir)/$(base-prefix)$(libdir) $(libdirs)
ifneq (,$(objs))
libnames	:= $(libname) $(libnames)
libdeps		:= $(lib-libfile) $(libdeps)
endif

SIGN = scripts/sign_encrypt.py
TA_SIGN_KEY ?= keys/default_ta.pem

define process-lib
ifeq ($(lib-use-ld), y)
$(lib-libfile): $(objs)
	@echo '  LD      $$@'
	@mkdir -p $$(dir $$@)
	$$(q)$$(LD$(sm)) $(lib-ldflags) -o $$@ $$^
else
$(lib-libfile): $(objs)
	@$(cmd-echo-silent) '  AR      $$@'
	@mkdir -p $$(dir $$@)
	$$(q)rm -f $$@ && $$(AR$(sm)) rcs $$@ $$^
endif
ifeq ($(CFG_ULIBS_SHARED),y)
ifeq ($(sm)-$(CFG_TA_BTI),ta_arm64-y)
lib-ldflags$(lib-shlibfile) += $$(call ld-option,-z force-bti) --fatal-warnings
endif
$(lib-shlibfile): $(objs) $(lib-needed-so-files)
	@$(cmd-echo-silent) '  LD      $$@'
	@mkdir -p $$(dir $$@)
	$$(q)$$(LD$(sm)) $(lib-ldflags) -shared -z max-page-size=4096 \
		$(call ld-option,-z separate-loadable-segments) \
		$$(lib-ldflags$(lib-shlibfile)) \
		--soname=$(libuuid) -o $$@ $$(filter-out %.so,$$^) $(lib-Ll-args)

$(lib-shlibstrippedfile): $(lib-shlibfile)
	@$(cmd-echo-silent) '  OBJCOPY $$@'
	$$(q)$$(OBJCOPY$(sm)) --strip-unneeded $$< $$@

$(lib-shlibtafile): $(lib-shlibstrippedfile) $(TA_SIGN_KEY)
	@$(cmd-echo-silent) '  SIGN    $$@'
	$$(q)$$(PYTHON3) $$(SIGN) --key $(TA_SIGN_KEY) --uuid $(libuuid) --in $$< --out $$@

$(lib-libuuidln): $(lib-shlibfile)
	@$(cmd-echo-silent) '  LN      $$@'
	$$(q)ln -sf lib$(libname).so $$@
endif
endef #process-lib

$(eval $(call process-lib))

$(objs): $(conf-file)

# Clean residues from processing
objs		:=
libname		:=
libuuid		:=
lib-use-ld	:=
lib-shlibfile	:=
lib-shlibstrippedfile :=
lib-shlibtafile	:=
lib-libuuidln	:=
lib-needed-so-files :=
libl :=
