# Cleaning directories generated during a previous build,
# a failed previous build or even no previous build.
# Track build directories through 'cleanfiles'.

define _enum-parent-dirs
$(if $(1),$(1) $(if $(filter / ./,$(dir $(1))),,$(call enum-parent-dirs,$(dir $(1)))),)
endef

define enum-parent-dirs
$(call _enum-parent-dirs,$(patsubst %/,%,$(1)))
endef

define _reverse
$(if $(1),$(call _reverse,$(wordlist 2,$(words $(1)),$(1)))) $(firstword $(1))
endef

# Returns the list of all existing output directories up to $(O) including all
# intermediate levels, in depth first order so that rmdir can process them in
# order. May return an empty string.
# Example: if cleanfiles is "foo/a/file1 foo/b/c/d/file2" and O=foo, this will
# return "foo/b/c/d foo/b/c foo/b foo/a" (assuming all exist).
define cleandirs-for-rmdir
$(eval _O:=$(if $(O),$(O),.))$(wildcard $(addprefix $(_O)/,$(call _reverse,
	$(sort $(foreach d,$(patsubst $(_O)/%,%,$(dir $(cleanfiles))),
			   $(call enum-parent-dirs,$(d)))))))
endef

RMDIR := rmdir --ignore-fail-on-non-empty

# Remove files with "rm -f".
# Split (possibly huge) file list into more manageable lines
# (200 files at a time), to minimize the odds of having:
# "/bin/bash: Argument list too long"
define do-rm-f
        $(call _do-rm-f, $(wordlist 1, 200, $(1))) \
        $(eval _tail := $(wordlist 201, $(words $(1)), $(1)))
        $(if $(_tail), $(call do-rm-f, $(_tail)))
endef

define _do-rm-f
        ${q}rm -f $1
endef
