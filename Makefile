SHELL = /bin/bash

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
PLATFORM_FLAVOR ?= qemu_virt
O		?= out/$(ARCH)-plat-$(PLATFORM)

arch_$(ARCH)	:= y

ifneq ($O,)
out-dir := $O
endif

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

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   .'
	${q}rm -f $(cleanfiles)

.PHONY: cscope
cscope:
	@echo '  CSCOPE  .'
	${q}rm -f cscope.*
	${q}find $(PWD) -name "*.[chSs]" > cscope.files
	${q}cscope -b -q -k
