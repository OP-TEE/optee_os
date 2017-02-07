SHELL = /bin/bash

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


include core/core.mk

# Platform config is supposed to assign the targets
ta-targets ?= user_ta

ifeq ($(CFG_WITH_USER_TA),y)
define build-ta-target
ta-target := $(1)
include ta/ta.mk
endef
$(foreach t, $(ta-targets), $(eval $(call build-ta-target, $(t))))
endif

include mk/cleandirs.mk

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   $(out-dir)'
	${q}rm -f $(cleanfiles)
	${q}dirs="$(call cleandirs-for-rmdir)"; if [ "$$dirs" ]; then $(RMDIR) $$dirs; fi
	@if [ "$(out-dir)" != "$(O)" ]; then $(cmd-echo-silent) '  CLEAN   $(O)'; fi
	${q}if [ -d "$(O)" ]; then $(RMDIR) $(O); fi

.PHONY: cscope
cscope:
	@echo '  CSCOPE  .'
	${q}rm -f cscope.*
	${q}find $(PWD) -name "*.[chSs]" > cscope.files
	${q}cscope -b -q -k
