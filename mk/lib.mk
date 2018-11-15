# Input
#
# libname	tells the name of the lib and
# libdir	tells directory of lib which also is used as input to
#		mk/subdir.mk
# conf-file     [optional] if set, all objects will depend on $(conf-file)
#
# Output
#
# updated cleanfiles and
# updated libfiles, libdirs, libnames and libdeps


subdirs = $(libdir)
include mk/subdir.mk
ifneq ($(sm),core) # User-mode
ifeq ($(CFG_ULIBS_GPROF),y)
cflags-lib$(libname)-$(sm) += -pg
endif
endif
include mk/compile.mk

lib-libfile	 = $(out-dir)/$(base-prefix)$(libdir)/lib$(libname).a
cleanfiles	:= $(cleanfiles) $(lib-libfile)
libfiles	:= $(lib-libfile) $(libfiles)
libdirs 	:= $(out-dir)/$(base-prefix)$(libdir) $(libdirs)
libnames	:= $(libname) $(libnames)
libdeps		:= $(lib-libfile) $(libdeps)

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
endef #process-lib

$(eval $(call process-lib))

$(objs): $(conf-file)

# Clean residues from processing
objs		:=
libname		:=
lib-use-ld	:=
