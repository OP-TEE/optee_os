SHELL = /bin/bash

.PHONY: all
all:

.PHONY: mem_usage
mem_usage:

# If $(PLATFORM) is defined and contains a hyphen, parse it as
# $(PLATFORM)-$(PLATFORM_FLAVOR) for convenience
ifneq (,$(findstring -,$(PLATFORM)))
ops := $(join PLATFORM PLATFORM_FLAVOR,$(addprefix =,$(subst -, ,$(PLATFORM))))
$(foreach op,$(ops),$(eval override $(op)))
endif

# Make these default for now
ARCH            ?= arm32
PLATFORM        ?= stm
O		?= out/$(ARCH)-plat-$(PLATFORM)

arch_$(ARCH)	:= y

ifneq ($O,)
out-dir := $O
endif

ifneq ($V,1)
q := @
cmd-echo := true
else
q :=
cmd-echo := echo
endif

include core/core.mk

include ta/ta.mk

.PHONY: clean
clean:
	@echo '  CLEAN   .'
	${q}rm -f $(cleanfiles)

.PHONY: cscope
cscope:
	@echo '  CSCOPE  .'
	${q}rm -f cscope.*
	${q}find $(PWD) -name "*.[chSs]" > cscope.files
	${q}cscope -b -q -k
