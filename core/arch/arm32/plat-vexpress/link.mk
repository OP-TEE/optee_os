link-out-dir = $(out-dir)/core

link-script = $(platform-dir)/kern.ld.S
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

AWK	 = awk


link-ldflags  = $(LDFLAGS)
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment
link-ldflags += --fatal-warnings
link-ldflags += --print-gc-sections

link-ldadd  = $(LDADD)
link-ldadd += $(addprefix -L,$(libdirs))
link-ldadd += $(addprefix -l,$(libnames))
ldargs-tee.elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcccore)

link-script-cppflags := -DASM=1 \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinccore) $(CPPFLAGS) \
		$(addprefix -I,$(incdirscore) $(link-out-dir)) \
		$(cppflagscore))

entries-unpaged += tee_pager_abort_handler
entries-unpaged += thread_init_vbar
entries-unpaged += sm_init
entries-unpaged += core_init_mmu_regs
entries-unpaged += main_cpu_on_handler
entries-unpaged += main_init_secondary
entries-unpaged += stack_tmp_top
objs-unpaged := \
	$(filter-out $(addprefix $(out-dir)/, $(objs-unpaged-rem)), $(objs))
ldargs-unpaged := -i --gc-sections \
	$(addprefix -u, $(entries-unpaged)) \
	$(objs-unpaged) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/unpaged.o
$(link-out-dir)/unpaged.o: $(objs-unpaged) $(libdeps) $(MAKEFILE_LIST)
	@echo '  LD      $@'
	$(q)$(LDcore) $(ldargs-unpaged) -o $@

cleanfiles += $(link-out-dir)/text_unpaged.ld.S:
$(link-out-dir)/text_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@echo '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/gen_ld_text_sects.awk > $@

cleanfiles += $(link-out-dir)/rodata_unpaged.ld.S:
$(link-out-dir)/rodata_unpaged.ld.S: $(link-out-dir)/unpaged.o
	@echo '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | \
		${AWK} -f ./scripts/gen_ld_rodata_sects.awk > $@

objs-init-rem += core/arch/arm32/tee/arch_svc.o
objs-init-rem += core/arch/arm32/tee/arch_svc_asm.o
objs-init-rem += core/arch/arm32/plat-vexpress/plat_tee_func.o
objs-init-rem += core/arch/arm32/tee/init.o
entries-init += _start
objs-init := \
	$(filter-out $(addprefix $(out-dir)/, $(objs-init-rem)), $(objs))
ldargs-init := -i --gc-sections \
	$(addprefix -u, $(entries-init)) \
	$(objs-init) $(link-ldadd) $(libgcccore)
cleanfiles += $(link-out-dir)/init.o
$(link-out-dir)/init.o: $(objs-init) $(libdeps) $(MAKEFILE_LIST)
	@echo '  LD      $@'
	$(q)$(LDcore) $(ldargs-init) -o $@

cleanfiles += $(link-out-dir)/text_init.ld.S:
$(link-out-dir)/text_init.ld.S: $(link-out-dir)/init.o
	@echo '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/gen_ld_text_sects.awk > $@

cleanfiles += $(link-out-dir)/rodata_init.ld.S:
$(link-out-dir)/rodata_init.ld.S: $(link-out-dir)/init.o
	@echo '  GEN     $@'
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
	@echo '  CPP     $@'
	@mkdir -p $(dir $@)
	$(q)$(CPPcore) -Wp,-P,-MT,$@,-MD,$(link-script-dep) \
		$(link-script-cppflags) $< > $@

all: $(link-out-dir)/tee.elf
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.map
$(link-out-dir)/tee.elf: $(objs) $(libdeps) $(link-script-pp)
	@echo '  LD      $@'
	$(q)$(LDcore) $(ldargs-tee.elf) -o $@

all: $(link-out-dir)/tee.dmp
cleanfiles += $(link-out-dir)/tee.dmp
$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@echo '  OBJDUMP $@'
	$(q)$(OBJDUMPcore) -l -x -d $< > $@

pageable_sections := .*_pageable
init_sections := .*_init
cleanfiles += $(link-out-dir)/tee-pager.bin
$(link-out-dir)/tee-pager.bin: $(link-out-dir)/tee.elf
	@echo '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--remove-section="$(pageable_sections)" \
		--remove-section="$(init_sections)" \
		$< $@

cleanfiles += $(link-out-dir)/tee-pageable.bin
$(link-out-dir)/tee-pageable.bin: $(link-out-dir)/tee.elf
	@echo '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary \
		--only-section="$(init_sections)" \
		--only-section="$(pageable_sections)" \
		$< $@

cleanfiles += $(link-out-dir)/tee-init_size.txt
$(link-out-dir)/tee-init_size.txt: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep __init_size | sed 's/ .*$$//' >> $@

cleanfiles += $(link-out-dir)/tee-init_load_addr.txt
$(link-out-dir)/tee-init_load_addr.txt: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
	@echo -n 0x > $@
	$(q)$(NMcore) $< | grep ' _start' | sed 's/ .*$$//' >> $@

cleanfiles += $(link-out-dir)/tee-init_mem_usage.txt
$(link-out-dir)/tee-init_mem_usage.txt: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
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
	@echo '  GEN     $@'
	$(q)./scripts/gen_hashed_bin.py \
		--arch 0 \
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
	@echo '  GEN     $@'
	$(q)$(NMcore) --print-size --reverse-sort --size-sort $< > $@

cleanfiles += $(link-out-dir)/tee.mem_usage
ifneq ($(filter mem_usage,$(MAKECMDGOALS)),)
mem_usage: $(link-out-dir)/tee.mem_usage

$(link-out-dir)/tee.mem_usage: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
	$(q)$(READELFcore) -a -W $< | ${AWK} -f ./scripts/mem_usage.awk > $@
endif
