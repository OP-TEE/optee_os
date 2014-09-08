link-out-dir = $(out-dir)/core

link-script = $(platform-dir)/kern.ld.S
link-script-pp = $(link-out-dir)/kern.ld
link-script-dep = $(link-out-dir)/.kern.ld.d

AWK	 = awk

all: $(link-out-dir)/tee.elf $(link-out-dir)/tee.dmp $(link-out-dir)/tee.bin
all: $(link-out-dir)/tee.symb_sizes
cleanfiles += $(link-out-dir)/tee.elf $(link-out-dir)/tee.dmp $(link-out-dir)/tee.map
cleanfiles += $(link-out-dir)/tee.bin
cleanfiles += $(link-out-dir)/tee.symb_sizes
cleanfiles += $(link-script-pp) $(link-script-dep)

link-ldflags  = $(LDFLAGS)
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/tee.map
link-ldflags += --sort-section=alignment

link-ldadd  = $(LDADD)
link-ldadd += $(addprefix -L,$(libdirs))
link-ldadd += $(addprefix -l,$(libnames))
ldargs-tee.elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcc)

link-script-cppflags :=  \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinc) $(CPPFLAGS) \
		$(addprefix -I,$(incdirs$(sm))) $(cppflags$(sm)))


-include $(link-script-dep)

$(link-script-pp): $(link-script)
	@echo '  CPP     $@'
	@mkdir -p $(dir $@)
	$(q)$(CPP) -Wp,-P,-MT,$@,-MD,$(link-script-dep) \
		$(link-script-cppflags) $< > $@


$(link-out-dir)/tee.elf: $(objs) $(libdeps) $(link-script-pp)
	@echo '  LD      $@'
	$(q)$(LD) $(ldargs-tee.elf) -o $@

$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@echo '  OBJDUMP $@'
	$(q)$(OBJDUMP) -l -x -d $< > $@

$(link-out-dir)/tee.bin: $(link-out-dir)/tee.elf
	@echo '  OBJCOPY $@'
	$(q)$(OBJCOPY) -O binary $< $@

$(link-out-dir)/tee.symb_sizes: $(link-out-dir)/tee.elf
	@echo '  GEN     $@'
	$(q)$(NM) --print-size --reverse-sort --size-sort $< > $@
