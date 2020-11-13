# Input
#
# subdirs	tells the subdirectories to descend
#
# Output
#
# set     srcs gen-srcs
# set     cflags-$(oname) cflags-remove-$(oname)
#         cxxflags-$(oname) cxxflags-remove-$(oname)
#         aflags-$(oname) aflags-remove-$(oname)
#         cppflags-$(oname) cppflags-remove-$(oname)
#         incdirs-$(oname)
#         incdirs-lib$(libname)-$(sm)  [if libname is defined]
#         cppflags-lib$(libname)-$(sm) [if libname is defined]
#         cflags-lib$(libname)-$(sm)   [if libname is defined]
#         cxxflags-lib$(libname)-$(sm) [if libname is defined]
# for each file found, oname is the name of the object file for corresponding
# source file

srcs :=
gen-srcs :=
asm-defines-files :=

define process-subdir-srcs-y
ifeq ($$(sub-dir),.)
srcs 				+= $1
oname				:= $(out-dir)/$(base-prefix)$(basename $1).o
else
ifneq ($(filter /%,$(1)),)
# $1 is an absolute path - start with "/"
srcs 				+= $1
oname				:= $(out-dir)/$(base-prefix)$(basename $1).o
else
srcs				+= $(sub-dir)/$1
oname				:= $(out-dir)/$(base-prefix)$(basename $$(sub-dir)/$1).o
endif
endif
cflags-$$(oname) 		:= $$(cflags-y) $$(cflags-$(1)-y)
cflags-remove-$$(oname) 	:= $$(cflags-remove-y) \
					$$(cflags-remove-$(1)-y)
cxxflags-$$(oname) 		:= $$(cxxflags-y) $$(cxxflags-$(1)-y)
cxxflags-remove-$$(oname) 	:= $$(cxxflags-remove-y) \
					$$(cxxflags-remove-$(1)-y)
cppflags-$$(oname) 		:= $$(cppflags-y) $$(cppflags-$(1)-y)
cppflags-remove-$$(oname) 	:= $$(cppflags-remove-y) \
					$$(cppflags-remove-$(1)-y)
aflags-$$(oname) 		:= $$(aflags-y) $$(aflags-$(1)-y)
aflags-remove-$$(oname) 	:= $$(aflags-remove-y) \
					$$(aflags-remove-$(1)-y)
incdirs-$$(oname)		:= $$(thissubdir-incdirs) $$(addprefix $(sub-dir)/,$$(incdirs-$(1)-y))
# Clear local filename specific variables to avoid accidental reuse
# in another subdirectory
cflags-$(1)-y 			:=
cflags-remove-$(1)-y		:=
cflags-lib-y			:=
cxxflags-$(1)-y 		:=
cxxflags-remove-$(1)-y		:=
cxxflags-lib-y			:=
cppflags-$(1)-y			:=
cppflags-remove-$(1)-y		:=
cppflags-lib-y			:=
aflags-$(1)-y 			:=
aflags-remove-$(1)-y		:=
incdirs-$(1)-y			:=
fname				:=
oname				:=
endef #process-subdir-srcs-y

define process-subdir-gensrcs-helper
# $1 gensrc-y element
# $2 full path and name of generated source file
# $3 full path and name of object file compiled from source file
# $4 full path to out directory
# $5 y if $2 must be generated before $(sm) starts building (e.g., .h file)

gen-srcs			+= $2
cleanfiles			+= $2
oname				:= $3

FORCE-GENSRC$(sm): $(if $(filter y,$5),$2,)

$$(addprefix $4,$$(produce-additional-$1)): $2

subdir-$2 := $$(sub-dir)
recipe-$2 := $$(recipe-$1)
$2: $$(depends-$1)
	@$(cmd-echo-silent) '  GEN     $2'
	$(q)mkdir -p $4
	$(q)$$(recipe-$2)

cflags-$$(oname) 		:= $$(cflags-y) $$(cflags-$(1)-y)
cflags-remove-$$(oname) 	:= $$(cflags-remove-y) \
					$$(cflags-remove-$(1)-y)
cxxflags-$$(oname) 		:= $$(cxxflags-y) $$(cxxflags-$(1)-y)
cxxflags-remove-$$(oname) 	:= $$(cxxflags-remove-y) \
					$$(cxxflags-remove-$(1)-y)
cppflags-$$(oname) 		:= $$(cppflags-y) $$(cppflags-$(1)-y)
cppflags-remove-$$(oname) 	:= $$(cppflags-remove-y) \
					$$(cppflags-remove-$(1)-y)
aflags-$$(oname) 		:= $$(aflags-y) $$(aflags-$(1)-y)
aflags-remove-$$(oname) 	:= $$(aflags-remove-y) \
					$$(aflags-remove-$(1)-y)
incdirs-$$(oname)		:= $$(thissubdir-incdirs) $$(addprefix $(sub-dir)/,$$(incdirs-$(1)-y))
# Clear local filename specific variables to avoid accidental reuse
# in another subdirectory
cflags-$(1)-y 			:=
cflags-remove-$(1)-y		:=
cflags-lib-y			:=
cxxflags-$(1)-y 			:=
cxxflags-remove-$(1)-y		:=
cxxflags-lib-y			:=
cppflags-$(1)-y			:=
cppflags-remove-$(1)-y		:=
cppflags-lib-y			:=
aflags-$(1)-y 			:=
aflags-remove-$(1)-y		:=
incdirs-$(1)-y			:=
fname				:=
oname				:=

endef #process-subdir-gensrcs-helper

define process-subdir-gensrcs-y
$$(eval $$(call process-subdir-gensrcs-helper,$1,$(sub-dir-out)/$$(produce-$1),$(sub-dir-out)/$(basename $(produce-$1)).o,$(sub-dir-out),$(force-gensrc-$1)))
endef #process-subdir-gensrcs-y

define process-subdir-asm-defines-y
asm-defines-files += $(sub-dir)/$1
endef #process-subdir-asm-defines-y

define process-subdir
sub-dir := $1
ifeq ($1,.)
sub-dir-out := $(patsubst %/,%,$(out-dir)/$(base-prefix))
else
sub-dir-out := $(out-dir)/$(base-prefix)$1
endif

include $1/sub.mk
sub-subdirs := $$(addprefix $1/,$$(subdirs-y))
incdirs$(sm) := $(incdirs$(sm)) $$(addprefix $1/,$$(global-incdirs-y))
thissubdir-incdirs := $(out-dir)/$(base-prefix)$1 $$(addprefix $1/,$$(incdirs-y))
ifneq ($$(libname),)
incdirs-lib$$(libname)-$$(sm) := $$(incdirs-lib$$(libname)-$$(sm)) $$(addprefix $1/,$$(incdirs-lib-y))
cflags-lib$$(libname)-$$(sm) := $$(cflags-lib$$(libname)-$$(sm)) $$(cflags-lib-y)
cxxflags-lib$$(libname)-$$(sm) := $$(cxxflags-lib$$(libname)-$$(sm)) $$(cxxflags-lib-y)
cppflags-lib$$(libname)-$$(sm) := $$(cppflags-lib$$(libname)-$$(sm)) $$(cppflags-lib-y)
endif

# Process files in current directory
$$(foreach g, $$(gensrcs-y), $$(eval $$(call process-subdir-gensrcs-y,$$(g))))
$$(foreach s, $$(srcs-y), $$(eval $$(call process-subdir-srcs-y,$$(s))))
$$(foreach a, $$(asm-defines-y), $$(eval $$(call process-subdir-asm-defines-y,$$(a))))
# Clear flags used when processing current directory
srcs-y :=
cflags-y :=
cflags-lib-y :=
cxxflags-y :=
cxxflags-lib-y :=
cppflags-y :=
cppflags-lib-y :=
aflags-y :=
cflags-remove-y :=
cxxflags-remove-y :=
aflags-remove-y :=
subdirs-y :=
global-incdirs-y :=
incdirs-lib-y :=
incdirs-y :=
gensrcs-y :=
this-out-dir :=
asm-defines-y :=

# Process subdirectories in current directory
$$(foreach sd, $$(sub-subdirs), $$(eval $$(call process-subdir,$$(sd))))
endef #process-subdir

# Top subdirectories
$(foreach sd, $(subdirs), $(eval $(call process-subdir,$(sd))))
