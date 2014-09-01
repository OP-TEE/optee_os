# Input
#
# libname	tells the name of the lib and
# libdir	tells directory of lib which also is used as input to
#		mk/subdir.mk
#
# Output
#
# updated cleanfiles and
# updated libfiles, libdirs, libnames and libdeps


subdirs = $(libdir)
include mk/subdir.mk
include mk/compile.mk

lib-libfile	 = $(out-dir)$(base-prefix)$(libdir)/lib$(libname).a
cleanfiles	:= $(cleanfiles) $(lib-libfile)
libfiles	:= $(lib-libfile) $(libfiles) 
libdirs 	:= $(out-dir)$(base-prefix)$(libdir) $(libdirs) 
libnames	:= $(libname) $(libnames)
libdeps		:= $(lib-libfile) $(libdeps) 

$(lib-libfile): $(objs)
	@echo '  AR      $@'
	@mkdir -p $(dir $@)
	$(q)$(AR) rcs $@ $^

# Clean residues from processing
objs		:=
