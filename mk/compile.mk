# Input
#
# The output from mk/sub.mk
# base-prefix
# conf-file [optional] if set, all objects will depend on $(conf-file)
#
# Output
#
# set	  objs
# update  cleanfiles
#
# Generates explicit rules for all objs

objs		:=

# Disable all builtin rules
.SUFFIXES:

comp-cflags$(sm) = -std=gnu99
comp-aflags$(sm) =
comp-cppflags$(sm) =

ifndef NOWERROR
comp-cflags$(sm)	+= -Werror
endif
comp-cflags$(sm)  	+= -fdiagnostics-show-option

comp-cflags-warns-high = \
	-Wall -Wcast-align  \
	-Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	-Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
	-Wmissing-declarations -Wmissing-format-attribute \
	-Wmissing-include-dirs -Wmissing-noreturn \
	-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
	-Wshadow -Wstrict-prototypes -Wswitch-default \
	-Wwrite-strings \
	-Wno-missing-field-initializers -Wno-format-zero-length
comp-cflags-warns-medium = \
	-Waggregate-return -Wredundant-decls
comp-cflags-warns-low = \
	-Wold-style-definition -Wstrict-aliasing=2 \
	-Wundef -pedantic \
	-Wdeclaration-after-statement

comp-cflags-warns-1:= $(comp-cflags-warns-high)
comp-cflags-warns-2:= $(comp-cflags-warns-1) $(comp-cflags-warns-medium)
comp-cflags-warns-3:= $(comp-cflags-warns-2) $(comp-cflags-warns-low)

WARNS		?= 3

comp-cflags$(sm)	+= $(comp-cflags-warns-$(WARNS))

CHECK ?= sparse

.PHONY: FORCE
FORCE:


define process_srcs
objs		+= $2
comp-dep-$2	:= $$(dir $2).$$(notdir $2).d
comp-cmd-file-$2:= $$(dir $2).$$(notdir $2).cmd
comp-sm-$2	:= $(sm)
comp-lib-$2	:= $(libname)

cleanfiles := $$(cleanfiles) $$(comp-dep-$2) $$(comp-cmd-file-$2) $2

ifeq ($$(filter %.c,$1),$1)
comp-q-$2 := CC
comp-flags-$2 = $$(filter-out $$(CFLAGS_REMOVE) $$(cflags-remove) \
			      $$(cflags-remove-$2), \
		   $$(CFLAGS) $$(CFLAGS_WARNS) \
		   $$(comp-cflags$$(comp-sm-$2)) $$(cflags$$(comp-sm-$2)) \
		   $$(cflags-lib$$(comp-lib-$2)) $$(cflags-$2))
ifeq ($C,1)
check-cmd-$2 = $(CHECK) $$(comp-cppflags-$2) $$<
echo-check-$2 := $(cmd-echo-silent)
echo-check-cmd-$2 = $(cmd-echo) $$(subst \",\\\",$$(check-cmd-$2))
endif

else ifeq ($$(filter %.S,$1),$1)
comp-q-$2 := AS
comp-flags-$2 = -DASM=1 $$(filter-out $$(AFLAGS_REMOVE) $$(aflags-remove) \
				      $$(aflags-remove-$2), \
			   $$(AFLAGS) $$(comp-aflags$$(comp-sm-$2)) \
			   $$(aflags$$(comp-sm-$2)) $$(aflags-$2))

else
$$(error "Don't know what to do with $1")
endif

comp-cppflags-$2 = $$(filter-out $$(CPPFLAGS_REMOVE) $$(cppflags-remove) \
			 $$(cppflags-remove-$2), \
		      $$(nostdinc$$(comp-sm-$2)) $$(CPPFLAGS) \
		      $$(addprefix -I,$$(incdirs$$(comp-sm-$2))) \
		      $$(addprefix -I,$$(incdirs-lib$$(comp-lib-$2))) \
		      $$(addprefix -I,$$(incdirs-$2)) \
		      $$(cppflags$$(comp-sm-$2)) \
		      $$(cppflags-lib$$(comp-lib-$2)) $$(cppflags-$2))

comp-flags-$2 += -MD -MF $$(comp-dep-$2) -MT $$@
comp-flags-$2 += $$(comp-cppflags-$2)

comp-cmd-$2 = $$(CC$(sm)) $$(comp-flags-$2) -c $$< -o $$@
comp-objcpy-cmd-$2 = $$(OBJCOPY$(sm)) \
	--rename-section .rodata=.rodata.$1 \
	--rename-section .rodata.str1.1=.rodata.str1.1.$1 \
	$2

# Assign defaults if unassigned
echo-check-$2 ?= true
echo-check-cmd-$2 ?= true
check-cmd-$2 ?= true

-include $$(comp-cmd-file-$2)
-include $$(comp-dep-$2)


$2: $1 FORCE
# Check if any prerequisites are newer than the target and
# check if command line has changed
	$$(if $$(strip $$(filter-out FORCE, $$?) \
	    $$(filter-out $$(comp-cmd-$2), $$(old-cmd-$2)) \
	    $$(filter-out $$(old-cmd-$2), $$(comp-cmd-$2))), \
		@set -e ;\
		mkdir -p $$(dir $2) ;\
		$$(echo-check-$2) '  CHECK   $$<' ;\
		$$(echo-check-cmd-$2) ;\
		$$(check-cmd-$2) ;\
		$(cmd-echo-silent) '  $$(comp-q-$2)      $$@' ;\
		$(cmd-echo) $$(subst \",\\\",$$(comp-cmd-$2)) ;\
		$$(comp-cmd-$2) ;\
		$(cmd-echo) $$(comp-objcpy-cmd-$2) ;\
		$$(comp-objcpy-cmd-$2) ;\
		echo "old-cmd-$2 := $$(subst \",\\\",$$(comp-cmd-$2))" > \
			$$(comp-cmd-file-$2) ;\
	)

endef

$(foreach f, $(srcs), $(eval $(call \
	process_srcs,$(f),$(out-dir)/$(base-prefix)$$(basename $f).o)))

# Handle generated source files, that is, files that are compiled from out-dir
$(foreach f, $(gen-srcs), $(eval $(call \
	process_srcs,$(out-dir)/$(f),$(out-dir)/$(base-prefix)$$(basename $f).o)))

$(objs): $(conf-file)
