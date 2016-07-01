link-out-dir = $(out-dir)/core

link-script = $(platform-dir)/kern.ld.S
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

AWK	 = awk


link-ldflags  = $(LDFLAGS)
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment
link-ldflags += --fatal-warnings
link-ldflags += --gc-sections

link-ldadd  = $(LDADD)
link-ldadd += $(addprefix -L,$(libdirs))
link-ldadd += $(addprefix -l,$(libnames))
ldargs-tee.elf := $(link-ldflags) $(objs) $(link-out-dir)/version.o \
	$(link-ldadd) $(libgcccore)

link-script-cppflags := -DASM=1 \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinccore) $(CPPFLAGS) \
		$(addprefix -I,$(incdirscore) $(link-out-dir)) \
		$(cppflagscore))

entries-unpaged += thread_init_vbar
entries-unpaged += sm_init
entries-unpaged += core_init_mmu_regs
entries-unpaged += sem_cpu_sync
entries-unpaged += generic_boot_get_handlers

ldargs-all_objs := -i $(objs) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/all_objs.o
$(link-out-dir)/all_objs.o: $(objs) $(libdeps) $(MAKEFILE_LIST)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-all_objs) -o $@

cleanfiles += $(link-out-dir)/unpaged_entries.txt
$(link-out-dir)/unpaged_entries.txt: $(link-out-dir)/all_objs.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) $< | \
		$(AWK) '/ ____keep_pager/ { printf "-u%s ", $$3 }' > $@

objs-unpaged-rem += core/arch/arm/tee/entry_std.o
objs-unpaged-rem += core/arch/arm/tee/arch_svc.o
objs-unpaged := \
	$(filter-out $(addprefix $(out-dir)/, $(objs-unpaged-rem)), $(objs))
ldargs-unpaged = -i --gc-sections $(addprefix -u, $(entries-unpaged))
ldargs-unpaged-objs := $(objs-unpaged) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/unpaged.o
$(link-out-dir)/unpaged.o: $(link-out-dir)/unpaged_entries.txt
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-unpaged) \
		`cat $(link-out-dir)/unpaged_entries.txt` \
		$(ldargs-unpaged-objs) -o $@

cleanfiles += $(link-out-dir)/text_unpaged.ld.S:
$(link-out-dir)/text_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/gen_ld_text_sects.awk > $@

cleanfiles += $(link-out-dir)/rodata_unpaged.ld.S:
$(link-out-dir)/rodata_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | \
		${AWK} -f ./scripts/gen_ld_rodata_sects.awk > $@


cleanfiles += $(link-out-dir)/init_entries.txt
$(link-out-dir)/init_entries.txt: $(link-out-dir)/all_objs.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) $< | \
		$(AWK) '/ ____keep_init/ { printf "-u%s", $$3 }' > $@

objs-init-rem += core/arch/arm/tee/arch_svc.o
objs-init-rem += core/arch/arm/tee/arch_svc_asm.o
objs-init-rem += core/arch/arm/tee/init.o
objs-init-rem += core/arch/arm/tee/entry_std.o
entries-init += _start
objs-init := \
	$(filter-out $(addprefix $(out-dir)/, $(objs-init-rem)), $(objs) \
		$(link-out-dir)/version.o)
ldargs-init := -i --gc-sections $(addprefix -u, $(entries-init))

ldargs-init-objs := $(objs-init) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/init.o
$(link-out-dir)/init.o: $(link-out-dir)/init_entries.txt
	$(call gen-version-o)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-init) \
		`cat $(link-out-dir)/init_entries.txt` \
		$(ldargs-init-objs) -o $@

cleanfiles += $(link-out-dir)/text_init.ld.S:
$(link-out-dir)/text_init.ld.S: $(link-out-dir)/init.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/gen_ld_text_sects.awk > $@

cleanfiles += $(link-out-dir)/rodata_init.ld.S:
$(link-out-dir)/rodata_init.ld.S: $(link-out-dir)/init.o
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | \
		${AWK} -f ./scripts/gen_ld_rodata_sects.awk > $@

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
	$(q)$(CPPcore) -Wp,-P,-MT,$@,-MD,$(link-script-dep) \
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

version-o-cflags = $(filter-out -g3,$(core-platform-cflags) \
			$(platform-cflags)) # Workaround objdump warning
DATE_STR = `date -u`
BUILD_COUNT_STR = `cat $(link-out-dir)/.buildcount`
define gen-version-o
	$(call update-buildcount,$(link-out-dir)/.buildcount)
	@$(cmd-echo-silent) '  GEN     $(link-out-dir)/version.o'
	$(q)echo -e "const char core_v_str[] =" \
		"\"$(TEE_IMPL_VERSION) \"" \
		"\"#$(BUILD_COUNT_STR) \"" \
		"\"$(DATE_STR) \"" \
		"\"$(CFG_KERN_LINKER_ARCH)\";\n" \
		| $(CCcore) $(version-o-cflags) \
			-xc - -c -o $(link-out-dir)/version.o
endef
$(link-out-dir)/version.o:
	$(call gen-version-o)

all: $(link-out-dir)/tee.elf
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.map
cleanfiles += $(link-out-dir)/version.o
cleanfiles += $(link-out-dir)/.buildcount
$(link-out-dir)/tee.elf: $(objs) $(libdeps) $(link-script-pp)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-tee.elf) -o $@

all: $(link-out-dir)/tee.dmp
cleanfiles += $(link-out-dir)/tee.dmp
$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMPcore) -l -x -d $< > $@

pageable_sections := .*_pageable
init_sections := .*_init
cleanfiles += $(link-out-dir)/tee-pager.bin
$(link-out-dir)/tee-pager.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--remove-section="$(pageable_sections)" \
		--remove-section="$(init_sections)" \
		$< $@

cleanfiles += $(link-out-dir)/tee-pageable.bin
$(link-out-dir)/tee-pageable.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--only-section="$(init_sections)" \
		--only-section="$(pageable_sections)" \
		$< $@

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

all: $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.bin
$(link-out-dir)/tee.bin: $(link-out-dir)/tee-pager.bin \
			 $(link-out-dir)/tee-pageable.bin \
			 $(link-out-dir)/tee-init_size.txt \
			 $(link-out-dir)/tee-init_load_addr.txt \
			 $(link-out-dir)/tee-init_mem_usage.txt \
			./scripts/gen_hashed_bin.py
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)./scripts/gen_hashed_bin.py \
		--arch $(if $(filter y,$(CFG_ARM64_core)),arm64,arm32) \
		--init_size `cat $(link-out-dir)/tee-init_size.txt` \
		--init_load_addr_lo \
			`cat $(link-out-dir)/tee-init_load_addr.txt` \
		--init_mem_usage `cat $(link-out-dir)/tee-init_mem_usage.txt` \
		--tee_pager_bin $(link-out-dir)/tee-pager.bin \
		--tee_pageable_bin $(link-out-dir)/tee-pageable.bin \
		--out $@


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
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/mem_usage.awk > $@
endif
