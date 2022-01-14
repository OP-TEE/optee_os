link-out-dir = $(out-dir)/core

link-script-dummy = $(arch-dir)/kernel/link_dummy.ld
link-script = $(if $(wildcard $(platform-dir)/kern.ld.S), \
		$(platform-dir)/kern.ld.S, \
		$(arch-dir)/kernel/kern.ld.S)
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

AWK	 = awk

link-ldflags  = $(LDFLAGS)
ifeq ($(CFG_CORE_ASLR),y)
link-ldflags += -pie -Bsymbolic -z notext -z norelro $(ldflag-apply-dynamic-relocs)
endif
ifeq ($(CFG_CORE_BTI),y)
# force-bti tells the linker to warn if some object files lack the .note.gnu.property
# section with the BTI flag, and to turn on the BTI flag in the output anyway. The
# resulting executable would likely fail at runtime so we use this flag along
# with the --fatal-warnings below to check and prevent this situation (with useful
# diagnostics).
link-ldflags += $(call ld-option,-z force-bti) --fatal-warnings
endif
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment
link-ldflags += --fatal-warnings
link-ldflags += --gc-sections

link-ldadd  = $(LDADD)
link-ldadd += $(ldflags-external)
link-ldadd += $(libdeps)
link-objs := $(filter-out \
	       $(out-dir)/$(platform-dir)/link_dummies_paged.o \
	       $(out-dir)/$(platform-dir)/link_dummies_init.o \
	       $(out-dir)/$(arch-dir)/kernel/link_dummies_paged.o \
	       $(out-dir)/$(arch-dir)/kernel/link_dummies_init.o, \
	       $(objs))
link-objs-init := $(filter-out \
		    $(out-dir)/$(platform-dir)/link_dummies_init.o \
		    $(out-dir)/$(arch-dir)/kernel/link_dummies_init.o, \
		    $(objs))
ldargs-tee.elf := $(link-ldflags) $(link-objs) $(link-out-dir)/version.o \
		  $(link-ldadd) $(libgcccore)

link-script-cppflags := \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinccore) $(CPPFLAGS) \
		$(addprefix -I,$(incdirscore) $(link-out-dir)) \
		$(cppflagscore))

ldargs-all_objs := -T $(link-script-dummy) --no-check-sections \
		   $(link-objs) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/all_objs.o
$(link-out-dir)/all_objs.o: $(objs) $(libdeps) $(MAKEFILE_LIST)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-all_objs) -o $@

cleanfiles += $(link-out-dir)/unpaged_entries.txt
$(link-out-dir)/unpaged_entries.txt: $(link-out-dir)/all_objs.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) $< | \
		$(AWK) '/ ____keep_pager/ { printf "-u%s ", $$3 }' > $@

unpaged-ldargs = -T $(link-script-dummy) --no-check-sections --gc-sections
unpaged-ldadd := $(objs) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/unpaged.o
$(link-out-dir)/unpaged.o: $(link-out-dir)/unpaged_entries.txt
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(unpaged-ldargs) \
		`cat $(link-out-dir)/unpaged_entries.txt` \
		$(unpaged-ldadd) -o $@

cleanfiles += $(link-out-dir)/text_unpaged.ld.S
$(link-out-dir)/text_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | \
		$(PYTHON3) ./scripts/gen_ld_sects.py .text. > $@

cleanfiles += $(link-out-dir)/rodata_unpaged.ld.S
$(link-out-dir)/rodata_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | \
		$(PYTHON3) ./scripts/gen_ld_sects.py .rodata. > $@


cleanfiles += $(link-out-dir)/init_entries.txt
$(link-out-dir)/init_entries.txt: $(link-out-dir)/all_objs.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) $< | \
		$(AWK) '/ ____keep_init/ { printf "-u%s ", $$3 }' > $@

init-ldargs := -T $(link-script-dummy) --no-check-sections --gc-sections
init-ldadd := $(link-objs-init) $(link-out-dir)/version.o  $(link-ldadd) \
	      $(libgcccore)
cleanfiles += $(link-out-dir)/init.o
$(link-out-dir)/init.o: $(link-out-dir)/init_entries.txt
	$(call gen-version-o)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(init-ldargs) \
		`cat $(link-out-dir)/init_entries.txt` \
		$(init-ldadd) -o $@

cleanfiles += $(link-out-dir)/text_init.ld.S
$(link-out-dir)/text_init.ld.S: $(link-out-dir)/init.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | \
		$(PYTHON3) ./scripts/gen_ld_sects.py .text. > $@

cleanfiles += $(link-out-dir)/rodata_init.ld.S
$(link-out-dir)/rodata_init.ld.S: $(link-out-dir)/init.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | $(PYTHON3) ./scripts/gen_ld_sects.py .rodata. > $@

-include $(link-script-dep)

link-script-extra-deps += $(link-out-dir)/text_unpaged.ld.S
link-script-extra-deps += $(link-out-dir)/rodata_unpaged.ld.S
link-script-extra-deps += $(link-out-dir)/text_init.ld.S
link-script-extra-deps += $(link-out-dir)/rodata_init.ld.S
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
DATE_STR = `LANG=C date -u $(date-opts)`
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
$(eval $(call check-link-objs))

all: $(link-out-dir)/tee.elf
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.map
cleanfiles += $(link-out-dir)/version.o
cleanfiles += $(link-out-dir)/.buildcount
cleanfiles += $(link-out-dir)/.tee.elf.cmd
$(link-out-dir)/tee.elf: $(link-objs) $(libdeps) $(link-script-pp) $(FORCE_LINK)
	@echo "old-link-objs := $(link-objs)" >$(link-out-dir)/.tee.elf.cmd
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-tee.elf) -o $@

all: $(link-out-dir)/tee.dmp
cleanfiles += $(link-out-dir)/tee.dmp
$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMPcore) -l -x -d $< > $@

cleanfiles += $(link-out-dir)/tee-pager.bin
$(link-out-dir)/tee-pager.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@echo Warning: $@ is deprecated
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_tee_pager_bin $@

cleanfiles += $(link-out-dir)/tee-pageable.bin
$(link-out-dir)/tee-pageable.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@echo Warning: $@ is deprecated
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_tee_pageable_bin $@

all: $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.bin
$(link-out-dir)/tee.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_tee_bin $@

all: $(link-out-dir)/tee-header_v2.bin
cleanfiles += $(link-out-dir)/tee-header_v2.bin
$(link-out-dir)/tee-header_v2.bin: $(link-out-dir)/tee.elf \
				   scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_header_v2 $@

all: $(link-out-dir)/tee-pager_v2.bin
cleanfiles += $(link-out-dir)/tee-pager_v2.bin
$(link-out-dir)/tee-pager_v2.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_pager_v2 $@

all: $(link-out-dir)/tee-pageable_v2.bin
cleanfiles += $(link-out-dir)/tee-pageable_v2.bin
$(link-out-dir)/tee-pageable_v2.bin: $(link-out-dir)/tee.elf \
				     scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(PYTHON3) scripts/gen_tee_bin.py --input $< --out_pageable_v2 $@

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
$(link-out-dir)/tee-raw.bin: $(link-out-dir)/tee.elf scripts/gen_tee_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)scripts/gen_tee_bin.py --input $< --out_tee_raw_bin $@

cleanfiles += $(link-out-dir)/tee.srec
$(link-out-dir)/tee.srec: $(link-out-dir)/tee-raw.bin
	@$(cmd-echo-silent) '  SREC    $@'
	$(q)$(OBJCOPYcore) -I binary -O srec $(SRECFLAGS) $< $@
