SHELL = bash

# It can happen that a makefile calls us, which contains an 'export' directive
# or the '.EXPORT_ALL_VARIABLES:' special target. In this case, all the make
# variables are added to the environment for each line of the recipes, so that
# any sub-makefile can use them.
# We have observed this can cause issues such as 'Argument list too long'
# errors as the shell runs out of memory.
# Since this Makefile won't call any sub-makefiles, and since the commands do
# not expect to implicitely obtain any make variable from the environment, we
# can safely cancel this export mechanism. Unfortunately, it can't be done
# globally, only by name. Let's unexport MAKEFILE_LIST which is by far the
# biggest one due to our way of tracking dependencies and compile flags
# (we include many *.cmd and *.d files).
unexport MAKEFILE_LIST

# Automatically delete corrupt targets (file updated but recipe exits with a
# nonzero status). Useful since a few recipes use shell redirection.
.DELETE_ON_ERROR:

include mk/macros.mk
include mk/checkconf.mk

.PHONY: all
all:

.PHONY: mem_usage
mem_usage:

# log and load eventual tee config file
# path is absolute or relative to current source root directory.
ifdef CFG_OPTEE_CONFIG
$(info Loading OPTEE configuration file $(CFG_OPTEE_CONFIG))
include $(CFG_OPTEE_CONFIG)
endif

# If $(PLATFORM) is defined and contains a hyphen, parse it as
# $(PLATFORM)-$(PLATFORM_FLAVOR) for convenience
ifneq (,$(findstring -,$(PLATFORM)))
ops := $(join PLATFORM PLATFORM_FLAVOR,$(addprefix =,$(subst -, ,$(PLATFORM))))
$(foreach op,$(ops),$(eval override $(op)))
endif

# Tools
GREP            ?= grep
AWK             ?= awk
# Make these default for now
ARCH            ?= arm
PLATFORM        ?= vexpress
# Default value for PLATFORM_FLAVOR is set in plat-$(PLATFORM)/conf.mk
ifeq ($O,)
O               := out
out-dir         := $(O)/$(ARCH)-plat-$(PLATFORM)
else
out-dir         := $(O)
endif

arch_$(ARCH)	:= y

ifneq ($V,1)
q := @
cmd-echo := true
cmd-echo-silent := echo
else
q :=
cmd-echo := echo
cmd-echo-silent := true
endif

ifneq ($(filter 4.%,$(MAKE_VERSION)),)  # make-4
ifneq ($(filter %s ,$(firstword x$(MAKEFLAGS))),)
cmd-echo-silent := true
endif
else                                    # make-3.8x
ifneq ($(findstring s, $(MAKEFLAGS)),)
cmd-echo-silent := true
endif
endif

SCRIPTS_DIR := scripts

# ---------------------------------------------------------------------------
# Kconfig integration
# ---------------------------------------------------------------------------
KCONFIG_KCONFIG    := $(CURDIR)/Kconfig
KCONFIG_CONFIG     := $(abspath $(out-dir))/.config
KCONFIG_AUTOCONFIG := $(abspath $(out-dir))/include/config/auto.conf
KCONFIG_AUTOHEADER := $(abspath $(out-dir))/include/generated/autoconf.h

# Compute the defconfig path immediately (`:=`) so that the conf.mk default
# for PLATFORM_FLAVOR (e.g. "qemu_virt") is not picked up when the user only
# specifies PLATFORM=vexpress.  At this point PLATFORM_FLAVOR is only set if
# the user passed it explicitly (directly or via "PLATFORM=foo-bar" parsing).
_defconfig-plat    := $(PLATFORM)$(if $(PLATFORM_FLAVOR),-$(PLATFORM_FLAVOR),)
KCONFIG_DEFCONFIG  ?= core/arch/$(ARCH)/configs/$(_defconfig-plat)_defconfig
KCONFIG_FRAGMENT   ?=

# Make fragment derived from .config: one "CFG_FOO ?= n" line per disabled
# symbol.  Including it injects the symbols into $(.VARIABLES) so that
# cfg-vars-by-prefix / cfg-make-define can emit the correct
# "/* CFG_FOO is not set */" entries in conf.h, matching the plain-Make
# behaviour where mk/config.mk had an explicit "CFG_FOO ?= n" default.
KCONFIG_NOTSET_MK  := $(abspath $(out-dir))/include/config/not-set.mk

# The kconfig tools (conf, mconf) use the CONFIG_ environment variable as the
# prefix for generated symbols.  By setting it to "CFG_" the generated
# .config, auto.conf and autoconf.h all use the existing CFG_* naming
# convention, keeping full backward compatibility with the rest of the tree.
export CONFIG_          := CFG_
export KCONFIG_CONFIG
export KCONFIG_AUTOCONFIG
export KCONFIG_AUTOHEADER
export srctree          := $(CURDIR)
export KCONFIG_DEFCONFIG

PYTHON            ?= python3
kconfig-py-dir    := $(CURDIR)/scripts/kconfiglib

# Targets that can run without a .config
no-dot-config-targets := clean cscope checkpatch checkpatch-staging \
                         checkpatch-working mem_usage

config-build :=
need-config  := 1

ifneq ($(filter $(no-dot-config-targets), $(MAKECMDGOALS)),)
ifeq ($(filter-out $(no-dot-config-targets), $(MAKECMDGOALS)),)
need-config :=
endif
endif

ifneq ($(filter config %config, $(MAKECMDGOALS)),)
config-build := 1
endif

ifdef config-build
# ---------------------------------------------------------------------------
# *config targets
# ---------------------------------------------------------------------------
.PHONY: config menuconfig nconfig oldconfig olddefconfig syncconfig \
        allnoconfig allyesconfig alldefconfig randconfig defconfig \
        savedefconfig listnewconfig

# Helper: create output dirs and run a kconfiglib Python script.
# $(1) = script basename  $(2) = optional extra args
define kconfig-py
	$(q)mkdir -p $(out-dir)/include/config $(dir $(KCONFIG_AUTOHEADER))
	$(q)$(PYTHON) $(kconfig-py-dir)/$(1) $(2)
endef

# Helper: run a *config script, then regenerate auto.conf + autoconf.h.
# $(1) = script basename  $(2) = optional extra args
define kconfig-py-with-sync
	$(call kconfig-py,$(1),$(2))
	$(q)$(PYTHON) $(kconfig-py-dir)/genconfig.py \
		--config-out $(KCONFIG_AUTOCONFIG) \
		$(KCONFIG_KCONFIG)
endef

# Line-oriented interactive config (kconfiglib oldconfig.py).
config oldconfig:
	$(call kconfig-py-with-sync,oldconfig.py,$(KCONFIG_KCONFIG))

olddefconfig:
	$(call kconfig-py-with-sync,olddefconfig.py,$(KCONFIG_KCONFIG))

allnoconfig:
	$(call kconfig-py-with-sync,allnoconfig.py,$(KCONFIG_KCONFIG))

allyesconfig:
	$(call kconfig-py-with-sync,allyesconfig.py,$(KCONFIG_KCONFIG))

alldefconfig:
	$(call kconfig-py-with-sync,alldefconfig.py,$(KCONFIG_KCONFIG))

randconfig:
	$(call kconfig-py-with-sync,randconfig.py,$(KCONFIG_KCONFIG))

listnewconfig:
	$(call kconfig-py,listnewconfig.py,$(KCONFIG_KCONFIG))

# ncurses TUI — nconfig has no Python equivalent, alias to menuconfig.
menuconfig nconfig:
	$(call kconfig-py-with-sync,menuconfig.py,$(KCONFIG_KCONFIG))

syncconfig:
	$(call kconfig-py,genconfig.py,--config-out $(KCONFIG_AUTOCONFIG) $(KCONFIG_KCONFIG))

defconfig:
	$(q)mkdir -p $(out-dir)/include/config $(dir $(KCONFIG_AUTOHEADER))
	$(q)if [ -n "$(KCONFIG_FRAGMENT)" ]; then \
		$(CURDIR)/scripts/merge_config.sh -m \
			$(abspath $(KCONFIG_DEFCONFIG)) $(abspath $(KCONFIG_FRAGMENT)) && \
		$(PYTHON) $(kconfig-py-dir)/olddefconfig.py $(KCONFIG_KCONFIG); \
	else \
		$(PYTHON) $(kconfig-py-dir)/defconfig.py \
			--kconfig $(KCONFIG_KCONFIG) \
			$(abspath $(KCONFIG_DEFCONFIG)); \
	fi
	$(q)$(PYTHON) $(kconfig-py-dir)/genconfig.py \
		--config-out $(KCONFIG_AUTOCONFIG) \
		$(KCONFIG_KCONFIG)

savedefconfig:
	$(q)mkdir -p $(dir $(KCONFIG_CONFIG))
	$(q)$(PYTHON) $(kconfig-py-dir)/savedefconfig.py \
		--kconfig $(KCONFIG_KCONFIG) \
		--out $(abspath $(KCONFIG_DEFCONFIG))

else  # !config-build
# ---------------------------------------------------------------------------
# Normal build targets
# ---------------------------------------------------------------------------

# Kconfig-generated variable assignments must exist before the rest of the
# build system is parsed.  If auto.conf is missing the user forgot to run
# defconfig first; emit a clear error rather than silently falling back to
# the mk/config.mk defaults (which we want to retire).
ifdef need-config
ifeq ($(wildcard $(KCONFIG_AUTOCONFIG)),)
$(error .config not found - run: make PLATFORM=$(PLATFORM) defconfig)
endif
include $(KCONFIG_AUTOCONFIG)
include $(KCONFIG_NOTSET_MK)
endif

# Guard: error if a Kconfig-owned CFG_ symbol is given on the Make command
#
# TODO: Remove once the Kconfig switch is complete
_kconfig-syms := $(shell $(GREP) -rh --include=Kconfig '^config ' $(CURDIR) | $(AWK) '{print "CFG_" $$2}')

$(foreach _v,$(filter CFG_%,$(.VARIABLES)),\
  $(if $(filter command line override,$(origin $(_v))),\
    $(if $(filter $(_v),$(_kconfig-syms)),\
      $(error $(_v) is Kconfig-managed — pass it at configure time: \
make PLATFORM=$(PLATFORM) KCONFIG_FRAGMENT=<fragment.config> defconfig))))

# Regenerate auto.conf / autoconf.h whenever .config changes.
$(KCONFIG_AUTOCONFIG): $(KCONFIG_CONFIG)
	$(q)mkdir -p $(dir $@) $(dir $(KCONFIG_AUTOHEADER))
	$(q)$(PYTHON) $(kconfig-py-dir)/genconfig.py \
		--config-out $@ \
		$(KCONFIG_KCONFIG)

# Regenerate not-set.mk whenever .config changes.  Each "# CFG_FOO is not
# set" line in .config becomes a "CFG_FOO ?= n" assignment, making the
# disabled symbol visible to cfg-vars-by-prefix so conf.h stays complete.
#
# TODO: Remove once the Kconfig switch is complete
$(KCONFIG_NOTSET_MK): $(KCONFIG_CONFIG)
	$(q)mkdir -p $(dir $@)
	$(q)sed -n 's/^# \($(CONFIG_)[A-Z0-9_]*\) is not set$$/\1 ?= n/p' $< > $@

endif  # !config-build

include core/core.mk

# Platform/arch config is supposed to assign the targets
ta-targets ?= invalid
$(call force,default-user-ta-target,$(firstword $(ta-targets)))

ifeq ($(CFG_WITH_USER_TA),y)
include ldelf/ldelf.mk
define build-ta-target
ta-target := $(1)
include ta/ta.mk
endef
$(foreach t, $(ta-targets), $(eval $(call build-ta-target, $(t))))

# Build user TAs included in this git
ifeq ($(CFG_BUILD_IN_TREE_TA),y)
define build-user-ta
ta-mk-file := $(1)
include ta/mk/build-user-ta.mk
endef
$(foreach t, $(sort $(wildcard ta/*/user_ta.mk)), $(eval $(call build-user-ta,$(t))))
endif
endif

include mk/cleandirs.mk

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   $(out-dir)'
	$(call do-rm-f, $(cleanfiles))
	${q}dirs="$(call cleandirs-for-rmdir)"; if [ "$$dirs" ]; then $(RMDIR) $$dirs; fi
	@if [ "$(out-dir)" != "$(O)" ]; then $(cmd-echo-silent) '  CLEAN   $(O)'; fi
	${q}if [ -d "$(O)" ]; then $(RMDIR) $(O); fi
	${q}rm -f compile_commands.json

.PHONY: cscope
cscope:
	@echo '  CSCOPE  .'
	${q}rm -f cscope.*
	${q}find $(PWD) -name "*.[chSs]" | grep -v export-ta_ | \
		grep -v -F _init.ld.S | grep -v -F _unpaged.ld.S > cscope.files
	${q}cscope -b -q -k

.PHONY: checkpatch checkpatch-staging checkpatch-working
checkpatch: checkpatch-staging checkpatch-working

checkpatch-working:
	${q}./scripts/checkpatch.sh

checkpatch-staging:
	${q}./scripts/checkpatch.sh --cached
