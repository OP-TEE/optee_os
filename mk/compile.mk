# Input
#
# The output from mk/sub.mk
# base-prefix
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
else ifeq ($$(filter %.S,$1),$1)
comp-q-$2 := AS
comp-flags-$2 = -DASM=1 $$(filter-out $$(AFLAGS_REMOVE) $$(aflags-remove) \
				      $$(aflags-remove-$2), \
			   $$(AFLAGS) $$(comp-aflags$$(comp-sm-$2)) \
			   $$(aflags$$(comp-sm-$2)) $$(aflags-$2))
else
$$(error "Don't know what to do with $1")
endif


comp-flags-$2 += -MD -MF $$(comp-dep-$2) -MT $$@ \
	   $$(filter-out $$(CPPFLAGS_REMOVE) $$(cppflags-remove) \
			 $$(cppflags-remove-$2), \
	      $$(nostdinc) $$(CPPFLAGS) \
	      $$(addprefix -I,$$(incdirs$$(comp-sm-$2))) \
	      $$(addprefix -I,$$(incdirs-lib$$(comp-lib-$2))) \
	      $$(addprefix -I,$$(incdirs-$2)) \
	      $$(cppflags$$(comp-sm-$2)) \
	      $$(cppflags-lib$$(comp-lib-$2)) $$(cppflags-$2))

comp-cmd-$2 = $$(CC) $$(comp-flags-$2) -c $$< -o $$@

-include $$(comp-cmd-file-$2)
-include $$(comp-dep-$2)


$2: $1 FORCE
# Check if any prerequisites are newer than the target and
# check if command line has changed
	$$(if $$(strip $$?  $$(filter-out $$(comp-cmd-$2), $$(old-cmd-$2)) \
	    $$(filter-out $$(old-cmd-$2), $$(comp-cmd-$2))), \
		@set -e ;\
		mkdir -p $$(dir $2) ;\
		echo '  $$(comp-q-$2)      $$@' ;\
		$(cmd-echo) $$(subst \",\\\",$$(comp-cmd-$2)) ;\
		$$(comp-cmd-$2) ;\
		echo "old-cmd-$2 := $$(subst \",\\\",$$(comp-cmd-$2))" > \
			$$(comp-cmd-file-$2) ;\
	)

endef

$(foreach f, $(srcs), $(eval $(call \
	process_srcs,$(f),$(out-dir)/$(base-prefix)$$(basename $f).o)))
