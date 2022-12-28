link-out-dir = $(out-dir)/core

link-script = $(if $(wildcard $(platform-dir)/kern.ld.S), \
		$(platform-dir)/kern.ld.S, \
		$(arch-dir)/kernel/kern.ld.S)
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

link-ldflags-common += $(call ld-option,--no-warn-rwx-segments)

link-ldflags  = $(LDFLAGS)
ifeq ($(CFG_CORE_ASLR),y)
link-ldflags += -pie -Bsymbolic -z norelro $(ldflag-apply-dynamic-relocs)
endif

link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment
link-ldflags += --fatal-warnings
link-ldflags += --gc-sections
link-ldflags += $(link-ldflags-common)

link-ldadd  = $(LDADD)
link-ldadd += $(ldflags-external)
link-ldadd += $(libdeps)
link-objs := $(objs)

ldargs-tee.elf := $(link-ldflags) $(link-objs) $(link-out-dir)/version.o \
		  $(link-ldadd) $(libgcccore)

link-script-cppflags := \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinccore) $(CPPFLAGS) \
		$(addprefix -I,$(incdirscore) $(link-out-dir)) \
		$(cppflagscore))

ldargs-all_objs := -T $(link-script) --no-check-sections \
		   $(link-ldflags-common) \
		   $(link-objs) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/all_objs.o
$(link-out-dir)/all_objs.o: $(objs) $(libdeps) $(MAKEFILE_LIST)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-all_objs) -o $@

-include $(link-script-dep)

link-script-extra-deps += $(conf-file)
cleanfiles += $(link-script-pp) $(link-script-dep)
$(link-script-pp): $(link-script) $(link-script-extra-deps)
	@$(cmd-echo-silent) '  CPP     $@'
	@mkdir -p $(dir $@)
	$(q)$(CPPcore) -P -MT $@ -MD -MF $(link-script-dep) \
		$(link-script-cppflags) $< -o $@

define update-buildcount
	@$(cmd-echo-silent) '  UPD     $(1)'
	$(q)if [ ! -f $(1) ]; then \
		mkdir -p $(dir $(1)); \
		echo 1 >$(1); \
	else \
		expr 0`cat $(1)` + 1 >$(1); \
	fi
endef

# filter-out to workaround objdump warning
version-o-cflags = $(filter-out -g3,$(core-platform-cflags) \
			$(platform-cflags) $(cflagscore))
# SOURCE_DATE_EPOCH defined for reproducible builds
ifneq ($(SOURCE_DATE_EPOCH),)
date-opts = -d @$(SOURCE_DATE_EPOCH)
endif
DATE_STR = `LC_ALL=C date -u $(date-opts)`
BUILD_COUNT_STR = `cat $(link-out-dir)/.buildcount`
CORE_CC_VERSION = `$(CCcore) -v 2>&1 | grep "version " | sed 's/ *$$//'`
define gen-version-o
	$(call update-buildcount,$(link-out-dir)/.buildcount)
	@$(cmd-echo-silent) '  GEN     $(link-out-dir)/version.o'
	$(q)echo -e "const char core_v_str[] =" \
		"\"$(TEE_IMPL_VERSION) \"" \
		"\"($(CORE_CC_VERSION)) \"" \
		"\"#$(BUILD_COUNT_STR) \"" \
		"\"$(DATE_STR) \"" \
		"\"$(CFG_KERN_LINKER_ARCH)\";\n" \
		| $(CCcore) $(version-o-cflags) \
			-xc - -c -o $(link-out-dir)/version.o
endef

$(link-out-dir)/version.o:
	$(call gen-version-o)

-include $(link-out-dir)/.tee.elf.cmd
define check-link-objs
$(if $(strip $(filter-out $(link-objs), $(old-link-objs))
	     $(filter-out $(old-link-objs), $(link-objs))), FORCE_LINK := FORCE)
endef
#$(eval $(call check-link-objs))

all: $(link-out-dir)/tee.elf
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.map
cleanfiles += $(link-out-dir)/version.o
cleanfiles += $(link-out-dir)/.buildcount
cleanfiles += $(link-out-dir)/.tee.elf.cmd
$(link-out-dir)/tee.elf: $(link-objs) $(libdeps) $(link-script-pp) $(FORCE_LINK)
	$(call gen-version-o)
	@echo "old-link-objs := $(link-objs)" >$(link-out-dir)/.tee.elf.cmd
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-tee.elf) -o $@

all: $(link-out-dir)/tee.dmp
cleanfiles += $(link-out-dir)/tee.dmp
$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMPcore) -l -x -d $< > $@

all: $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.bin
$(link-out-dir)/tee.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(OBJCOPYcore) -O binary $< $@

all: $(link-out-dir)/tee.symb_sizes
cleanfiles += $(link-out-dir)/tee.symb_sizes
$(link-out-dir)/tee.symb_sizes: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) --print-size --reverse-sort --size-sort $< > $@

cleanfiles += $(link-out-dir)/tee.mem_usage
ifneq ($(filter mem_usage,$(MAKECMDGOALS)),)
mem_usage: $(link-out-dir)/tee.mem_usage

$(link-out-dir)/tee.mem_usage: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) ./scripts/mem_usage.py $< > $@
endif

cleanfiles += $(link-out-dir)/tee-raw.bin
$(link-out-dir)/tee-raw.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(OBJCOPYcore) -O binary $< $@

cleanfiles += $(link-out-dir)/tee.srec
$(link-out-dir)/tee.srec: $(link-out-dir)/tee-raw.bin
	@$(cmd-echo-silent) '  SREC    $@'
	$(q)$(OBJCOPYcore) -I binary -O srec $(SRECFLAGS) $< $@
