link-out-dir = $(out-dir)/core

link-script-dummy = core/arch/arm/kernel/link_dummy.ld
link-script = $(if $(wildcard $(platform-dir)/kern.ld.S), \
		$(platform-dir)/kern.ld.S, \
		core/arch/arm/kernel/kern.ld.S)
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

AWK	 = awk

link-ldflags  = $(LDFLAGS)
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment
link-ldflags += --fatal-warnings
link-ldflags += --gc-sections

link-ldadd  = $(LDADD)
link-ldadd += $(libdeps)
link-objs := $(filter-out $(out-dir)/core/arch/arm/kernel/link_dummies.o, \
			  $(objs))
ldargs-tee.elf := $(link-ldflags) $(link-objs) $(link-out-dir)/version.o \
		  $(link-ldadd) $(libgcccore)

link-script-cppflags := -DASM=1 \
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
		./scripts/gen_ld_sects.py .text. > $@

cleanfiles += $(link-out-dir)/rodata_unpaged.ld.S
$(link-out-dir)/rodata_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | \
		./scripts/gen_ld_sects.py .rodata. > $@


cleanfiles += $(link-out-dir)/init_entries.txt
$(link-out-dir)/init_entries.txt: $(link-out-dir)/all_objs.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) $< | \
		$(AWK) '/ ____keep_init/ { printf "-u%s ", $$3 }' > $@

init-ldargs := -T $(link-script-dummy) --no-check-sections --gc-sections
init-ldadd := $(objs) $(link-out-dir)/version.o  $(link-ldadd) $(libgcccore)
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
		./scripts/gen_ld_sects.py .text. > $@

cleanfiles += $(link-out-dir)/rodata_init.ld.S
$(link-out-dir)/rodata_init.ld.S: $(link-out-dir)/init.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -S -W $< | ./scripts/gen_ld_sects.py .rodata. > $@

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
	$(q)$(CPPcore) -Wp,-P,-MT,$@,$(MDflag),$(link-script-dep) \
		$(link-script-cppflags) $< > $@

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
DATE_STR = `date -u`
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

pageable_sections := .*_pageable
init_sections := .*_init
ifeq ($(CFG_ARM32_core)$(CFG_UNWIND),yy)
	remove-.ARM.exidx := --remove-section=".ARM.exidx"
	remove-.ARM.extab := --remove-section=".ARM.extab"
	only-.ARM.exidx := --only-section=".ARM.exidx"
	only-.ARM.extab := --only-section=".ARM.extab"
endif
cleanfiles += $(link-out-dir)/tee-pager.bin
$(link-out-dir)/tee-pager.bin: $(link-out-dir)/tee.elf \
		$(link-out-dir)/tee-data_end.txt
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--remove-section="$(pageable_sections)" \
		--remove-section="$(init_sections)" \
		$(remove-.ARM.exidx) $(remove-.ARM.extab) \
		--pad-to `cat $(link-out-dir)/tee-data_end.txt` \
		$< $@

cleanfiles += $(link-out-dir)/tee-pageable.bin
ifeq ($(CFG_WITH_PAGER),y)
$(link-out-dir)/tee-pageable.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--only-section="$(init_sections)" \
		--only-section="$(pageable_sections)" \
		$(only-.ARM.exidx) $(only-.ARM.extab) \
		$< $@
else
$(link-out-dir)/tee-pageable.bin:
	@$(cmd-echo-silent) '  TOUCH   $@'
	$(q)touch $@
endif

cleanfiles += $(link-out-dir)/tee-data_end.txt
$(link-out-dir)/tee-data_end.txt: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep __data_end | sed 's/ .*$$//' >> $@

cleanfiles += $(link-out-dir)/tee-init_size.txt
$(link-out-dir)/tee-init_size.txt: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep __init_size | sed 's/ .*$$//' >> $@

cleanfiles += $(link-out-dir)/tee-init_load_addr.txt
$(link-out-dir)/tee-init_load_addr.txt: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep ' _start' | sed 's/ .*$$//' >> $@

cleanfiles += $(link-out-dir)/tee-init_mem_usage.txt
$(link-out-dir)/tee-init_mem_usage.txt: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep ' __init_mem_usage' | sed 's/ .*$$//' >> $@

gen_hash_bin_deps :=	$(link-out-dir)/tee-pager.bin \
			$(link-out-dir)/tee-pageable.bin \
			$(link-out-dir)/tee-init_size.txt \
			$(link-out-dir)/tee-init_load_addr.txt \
			$(link-out-dir)/tee-init_mem_usage.txt \
			./scripts/gen_hashed_bin.py

define gen_hash_bin_cmd
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)load_addr=`cat $(link-out-dir)/tee-init_load_addr.txt` && \
	./scripts/gen_hashed_bin.py \
		--arch $(if $(filter y,$(CFG_ARM64_core)),arm64,arm32) \
		--init_size `cat $(link-out-dir)/tee-init_size.txt` \
		--init_load_addr_hi $$(($$load_addr >> 32 & 0xffffffff)) \
		--init_load_addr_lo $$(($$load_addr & 0xffffffff)) \
		--init_mem_usage `cat $(link-out-dir)/tee-init_mem_usage.txt` \
		--tee_pager_bin $(link-out-dir)/tee-pager.bin \
		--tee_pageable_bin $(link-out-dir)/tee-pageable.bin
endef

all: $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.bin
$(link-out-dir)/tee.bin: $(gen_hash_bin_deps)
	$(gen_hash_bin_cmd) --out $@

all: $(link-out-dir)/tee-header_v2.bin
cleanfiles += $(link-out-dir)/tee-header_v2.bin
$(link-out-dir)/tee-header_v2.bin: $(gen_hash_bin_deps)
	$(gen_hash_bin_cmd) --out_header_v2 $@

all: $(link-out-dir)/tee-pager_v2.bin
cleanfiles += $(link-out-dir)/tee-pager_v2.bin
$(link-out-dir)/tee-pager_v2.bin: $(gen_hash_bin_deps)
	$(gen_hash_bin_cmd) --out_pager_v2 $@

all: $(link-out-dir)/tee-pageable_v2.bin
cleanfiles += $(link-out-dir)/tee-pageable_v2.bin
$(link-out-dir)/tee-pageable_v2.bin: $(gen_hash_bin_deps)
	$(gen_hash_bin_cmd) --out_pageable_v2 $@

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
	$(q)./scripts/mem_usage.py $< > $@
endif
