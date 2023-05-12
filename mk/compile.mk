# Input
#
# The output from mk/sub.mk
# base-prefix
# conf-file [optional] if set, all objects will depend on $(conf-file)
# additional-compile-deps [optional] additional dependencies
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

comp-cflags$(sm) = -std=gnu11
comp-aflags$(sm) =
comp-cppflags$(sm) =

ifeq ($(CFG_WERROR),y)
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
	-Wno-missing-field-initializers -Wno-format-zero-length \
	-Wno-c2x-extensions
comp-cflags-warns-high += $(call cc-option,-Wpacked-not-aligned)
comp-cflags-warns-high += $(call cc-option,-Waddress-of-packed-member)
ifeq ($(CFG_WARN_DECL_AFTER_STATEMENT),y)
comp-cflags-warns-high += $(call cc-option,-Wdeclaration-after-statement)
endif
comp-cflags-warns-medium = \
	-Wredundant-decls
comp-cflags-warns-low = \
	-Wold-style-definition -Wstrict-aliasing=2 \
	-Wundef

comp-cflags-warns-1:= $(comp-cflags-warns-high)
comp-cflags-warns-2:= $(comp-cflags-warns-1) $(comp-cflags-warns-medium)
comp-cflags-warns-3:= $(comp-cflags-warns-2) $(comp-cflags-warns-low)

WARNS		?= 3

comp-cflags$(sm) += $(comp-cflags-warns-$(WARNS)) \
			$(comp-cflags-warns-$(COMPILER_$(sm)))

CHECK ?= sparse

.PHONY: FORCE
.PHONY: FORCE-GENSRC$(sm)
FORCE:
FORCE-GENSRC$(sm):


define process_srcs
objs		+= $2
comp-dep-$2	:= $$(dir $2).$$(notdir $2).d
comp-cmd-file-$2:= $$(dir $2).$$(notdir $2).cmd
comp-sm-$2	:= $(sm)
comp-lib-$2	:= $(libname)-$(sm)

cleanfiles := $$(cleanfiles) $$(comp-dep-$2) $$(comp-cmd-file-$2) $2

ifeq ($$(filter %.c,$1),$1)
comp-q-$2 := CC # one trailing space
comp-compiler-$2 := $$(CC$(sm))
comp-flags-$2 = $$(filter-out $$(CFLAGS_REMOVE) $$(cflags-remove) \
			      $$(cflags-remove-$$(comp-sm-$2)) \
			      $$(cflags-remove-$2), \
		   $$(CFLAGS$$(arch-bits-$$(comp-sm-$2))) $$(CFLAGS_WARNS) \
		   $$(comp-cflags$$(comp-sm-$2)) $$(cflags$$(comp-sm-$2)) \
		   $$(cflags-lib$$(comp-lib-$2)) $$(cflags-$2))
ifeq ($C,1)
check-cmd-$2 = $(CHECK) $$(comp-cppflags-$2) $$<
echo-check-$2 := $(cmd-echo-silent)
echo-check-cmd-$2 = $(cmd-echo) $$(subst \",\\\",$$(check-cmd-$2))
endif

else ifeq ($$(filter %.S,$1),$1)
comp-q-$2 := AS # one trailing space
comp-compiler-$2 := $$(CC$(sm))
comp-flags-$2 = $$(filter-out $$(AFLAGS_REMOVE) $$(aflags-remove) \
			      $$(aflags-remove-$$(comp-sm-$2)) \
			      $$(aflags-remove-$2), \
		   $$(AFLAGS) $$(comp-aflags$$(comp-sm-$2)) \
		   $$(aflags$$(comp-sm-$2)) $$(aflags-$2))

else ifeq ($$(filter %.cpp,$1),$1)
comp-q-$2 := CXX
comp-compiler-$2 := $$(CXX$(sm))
comp-flags-$2 = $$(filter-out $$(CXXFLAGS_REMOVE) $$(cxxflags-remove) \
			      $$(cxxflags-remove-$$(comp-sm-$2)) \
			      $$(cxxflags-remove-$2), \
		   $$(CXXFLAGS) $$(comp-cxxflags$$(comp-sm-$2)) \
		   $$(cxxflags$$(comp-sm-$2)) $$(cxxflags-$2))

else
$$(error "Don't know what to do with $1")
endif

comp-cppflags-$2 = $$(filter-out $$(CPPFLAGS_REMOVE) $$(cppflags-remove) \
				 $$(cppflags-remove-$$(comp-sm-$2)) \
				 $$(cppflags-remove-$2), \
		      $$(nostdinc$$(comp-sm-$2)) $$(CPPFLAGS) \
		      $$(addprefix -I,$$(incdirs$$(comp-sm-$2))) \
		      $$(addprefix -I,$$(incdirs-lib$$(comp-lib-$2))) \
		      $$(addprefix -I,$$(incdirs-$2)) \
		      $$(cppflags$$(comp-sm-$2)) \
		      $$(cppflags-lib$$(comp-lib-$2)) $$(cppflags-$2)) \
		      -D__FILE_ID__=$$(subst -,_,$$(subst /,_,$$(subst .,_,$1)))

comp-flags-$2 += -MD -MF $$(comp-dep-$2) -MT $$@
comp-flags-$2 += $$(comp-cppflags-$2)

comp-cmd-$2 = $$(comp-compiler-$2) $$(comp-flags-$2) -c $$< -o $$@
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


$2: $1 FORCE-GENSRC$(sm)
# Check if any prerequisites are newer than the target and
# check if command line has changed
	$$(if $$(strip $$(filter-out FORCE-GENSRC$(sm), $$?) \
	    $$(filter-out $$(comp-cmd-$2), $$(old-cmd-$2)) \
	    $$(filter-out $$(old-cmd-$2), $$(comp-cmd-$2))), \
		@set -e ;\
		mkdir -p $$(dir $2) ;\
		$$(echo-check-$2) '  CHECK   $$<' ;\
		$$(echo-check-cmd-$2) ;\
		$$(check-cmd-$2) ;\
		$(cmd-echo-silent) '  $$(comp-q-$2)     $$@' ;\
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
$(foreach f, $(gen-srcs), $(eval $(call process_srcs,$(f),$$(basename $f).o)))

# Handle specified source files, that is, files that have a specified path
# but where the object file should go into a specified out directory
$(foreach f, $(spec-srcs), $(eval $(call \
	process_srcs,$(f),$(spec-out-dir)/$$(notdir $$(basename $f)).o)))

$(objs): $(conf-file) $(additional-compile-deps)

define _gen-asm-defines-file
# c-filename in $1
# h-filename in $2
# s-filename in $3
# Dependencies in $4

FORCE-GENSRC$(sm): $(2)

comp-dep-$3	:= $$(dir $3)$$(notdir $3).d
comp-cmd-file-$3:= $$(dir $3)$$(notdir $3).cmd
comp-sm-$3	:= $(sm)

cleanfiles := $$(cleanfiles) $$(comp-dep-$3) $$(comp-cmd-file-$3) $3 $2

comp-flags-$3 = $$(filter-out $$(CFLAGS_REMOVE) $$(cflags-remove) \
			      $$(cflags-remove-$$(comp-sm-$3)) \
			      $$(cflags-remove-$3), \
		   $$(CFLAGS) $$(CFLAGS_WARNS) \
		   $$(comp-cflags$$(comp-sm-$3)) $$(cflags$$(comp-sm-$3)) \
		   $$(cflags-lib$$(comp-lib-$3)) $$(cflags-$3))

comp-cppflags-$3 = $$(filter-out $$(CPPFLAGS_REMOVE) $$(cppflags-remove) \
				 $$(cppflags-remove-$$(comp-sm-$3)) \
				 $$(cppflags-remove-$3), \
		      $$(nostdinc$$(comp-sm-$3)) $$(CPPFLAGS) \
		      $$(addprefix -I,$$(incdirs$$(comp-sm-$3))) \
		      $$(addprefix -I,$$(incdirs-lib$$(comp-lib-$3))) \
		      $$(addprefix -I,$$(incdirs-$3)) \
		      $$(cppflags$$(comp-sm-$3)) \
		      $$(cppflags-lib$$(comp-lib-$3)) $$(cppflags-$3))

comp-flags-$3 += -MD -MF $$(comp-dep-$3) -MT $$@
comp-flags-$3 += $$(comp-cppflags-$3)

comp-cmd-$3 = $$(CC$(sm)) $$(comp-flags-$3) -fverbose-asm -S $$< -o $$@


-include $$(comp-cmd-file-$3)
-include $$(comp-dep-$3)

$3: $1 $(conf-file) $(4) FORCE
# Check if any prerequisites are newer than the target and
# check if command line has changed
	$$(if $$(strip $$(filter-out FORCE, $$?) \
	    $$(filter-out $$(comp-cmd-$3), $$(old-cmd-$3)) \
	    $$(filter-out $$(old-cmd-$3), $$(comp-cmd-$3))), \
		@set -e ;\
		mkdir -p $$(dir $2) $$(dir $3) ;\
		$(cmd-echo-silent) '  CC      $$@'; 			\
		$(cmd-echo) $$(subst \",\\\",$$(comp-cmd-$3)) ;\
		$$(comp-cmd-$3) ;\
		echo "old-cmd-$3 := $$(subst \",\\\",$$(comp-cmd-$3))" > \
			$$(comp-cmd-file-$3) ;\
	)

guard-$2 := $$(subst -,_,$$(subst .,_,$$(subst /,_,$$(subst +,_,$2))))

$(2): $(3)
	$(q)set -e;							\
	$(cmd-echo-silent) '  CHK     $$@';			\
	mkdir -p $$(dir $$@);					\
	echo "#ifndef $$(guard-$2)" >$$@.tmp;			\
	echo "#define $$(guard-$2)" >>$$@.tmp;			\
	sed -ne 's|^.*==>\([^ ]*\) [\$$$$#]*\([-0-9]*\) \([^@/]*\).*|#define \1\t\2\t/* \3*/|p' \
	< $$< >>$$@.tmp;					\
	echo "#endif" >>$$@.tmp;				\
	$$(call mv-if-changed,$$@.tmp,$$@)

endef

define gen-asm-defines-file
$(call _gen-asm-defines-file,$1,$2,$(dir $2).$(notdir $(2:.h=.s)),$(asm-defines-$(notdir $(1))-deps))
endef

$(foreach f,$(asm-defines-files),$(eval $(call gen-asm-defines-file,$(f),$(out-dir)/$(sm)/include/generated/$(basename $(notdir $(f))).h)))

# Device tree source file compilation
DTC := dtc
DTC_FLAGS += -I dts -O dtb
DTC_FLAGS += -Wno-unit_address_vs_reg

define gen-dtb-file
# dts file path/name in $1
# dtb file path/name in $2

dtb-basename-$2	:= $$(basename $$(notdir $2))
dtb-predts-$2   := $$(dir $2)$$(dtb-basename-$2).pre.dts
dtb-predep-$2	:= $$(dir $2).$$(dtb-basename-$2).pre.dts.d
dtb-dep-$2	:= $$(dir $2).$$(notdir $2).d
dtb-cmd-file-$2	:= $$(dir $2).$$(notdir $2).cmd

cleanfiles := $$(cleanfiles) $2 \
		$$(dtb-predts-$2) $$(dtb-predep-$2) \
		$$(dtb-dep-$2) $$(dtb-cmd-file-$2)

dtb-cppflags-$2 := -Icore/include/ -x assembler-with-cpp -Ulinux -Uunix \
		   -E -ffreestanding $$(CPPFLAGS) \
		   -MD -MF $$(dtb-predep-$2) -MT $2

dtb-dtcflags-$2	:= $$(DTC_FLAGS) -d $$(dtb-dep-$2)

-include $$(dtb-dep-$2)
-include $$(dtb-predep-$2)
-include $$(dtb-cmd-file-$2)

dtb-precmd-$2 = $$(CPP$(sm)) $$(dtb-cppflags-$2) -o $$(dtb-predts-$2) $$<
dtb-cmd-$2 = $$(DTC) $$(dtb-dtcflags-$2) -o $$@ $$(dtb-predts-$2)

$2: $1 FORCE
# Check if any prerequisites are newer than the target and
# check if command line has changed
	$$(if $$(strip $$(filter-out FORCE, $$?) \
	    $$(filter-out $$(dtb-precmd-$2), $$(dtb-old-precmd-$2)) 	\
	    $$(filter-out $$(dtb-old-precmd-$2), $$(dtb-precmd-$2)) 	\
	    $$(filter-out $$(dtb-cmd-$2), $$(dtb-old-cmd-$2)) 		\
	    $$(filter-out $$(dtb-old-cmd-$2), $$(dtb-cmd-$2))),		\
		@set -e; 						\
		mkdir -p $$(dir $2); 					\
		$(cmd-echo-silent) '  CPP     $$(dtb-predts-$2)'; 	\
		$$(dtb-precmd-$2);					\
		$(cmd-echo-silent) '  DTC     $$@'; 			\
		$$(dtb-cmd-$2);						\
		echo "dtb-old-precmd-$2 := $$(subst \",\\\",$$(dtb-precmd-$2))" > \
			$$(dtb-cmd-file-$2) ;\
		echo "dtb-old-cmd-$2 := $$(subst \",\\\",$$(dtb-cmd-$2))" >> \
			$$(dtb-cmd-file-$2) ;\
	)

endef

additional-compile-deps :=
