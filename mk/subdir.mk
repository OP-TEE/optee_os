# Input
#
# subdirs	tells the subdirectories to descend
#
# Output
#
# set srcs
# set     cflags-$(oname) cflags-remove-$(oname)
#         aflags-$(oname) aflags-remove-$(oname)
#         cppflags-$(oname) cppflags-remove-$(oname)
# for each file found, oname is the name of the object file for corresponding
# source file

srcs :=

define process-subdir-srcs-y
ifeq ($$(sub-dir),.)
srcs 				+= $1
oname				:= $(out-dir)$(base-prefix)$(basename $1).o
else
ifneq ($(filter /%,$(1)),)
# $1 is an absolute path - start with "/"
srcs 				+= $1
oname				:= $(out-dir)$(base-prefix)$(basename $1).o
else
srcs				+= $(sub-dir)/$1
oname				:= $(out-dir)$(base-prefix)$(basename $$(sub-dir)/$1).o
endif
endif
cflags-$$(oname) 		:= $$(cflags-y) $$(cflags-$(1)-y)
cflags-remove-$$(oname) 	:= $$(cflags-remove-y) \
					$$(cflags-remove-$(1)-y)
cppflags-$$(oname) 		:= $$(cppflags-y) $$(cppflags-$(1)-y)
cppflags-remove-$$(oname) 	:= $$(cppflags-remove-y) \
					$$(cppflags-remove-$(1)-y)
aflags-$$(oname) 		:= $$(aflags-y) $$(aflags-$(1)-y)
aflags-remove-$$(oname) 	:= $$(aflags-remove-y) \
					$$(aflags-remove-$(1)-y)
# Clear local filename specific variables to avoid accidental reuse
# in another subdirectory
cflags-$(1)-y 			:=
cflags-remove-$(1)-y		:=
cppflags-$(1)-y			:=
cppflags-remove-$(1)-y		:=
aflags-$(1)-y 			:=
aflags-remove-$(1)-y		:=
fname				:=
oname				:=
endef #process-subdir-srcs-y

define process-subdir
sub-dir := $1
include $1/sub.mk
sub-subdirs := $$(addprefix $1/,$$(subdirs-y))
incdirs$(sm) := $(incdirs$(sm)) $$(addprefix $1/,$$(global-incdirs-y))

# Process files in current directory
$$(foreach s, $$(srcs-y), $$(eval $$(call process-subdir-srcs-y,$$(s))))
# Clear flags used when processing current directory
srcs-y :=
cflags-y :=
cppflags-y :=
aflags-y :=
cflags-remove-y :=
subdirs-y :=
global-incdirs-y :=

# Process subdirectories in current directory
$$(foreach sd, $$(sub-subdirs), $$(eval $$(call process-subdir,$$(sd))))
endef #process-subdir

# Top subdirectories
$(foreach sd, $(subdirs), $(eval $(call process-subdir,$(sd))))
