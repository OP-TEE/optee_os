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
ldargs-tee.elf := $(link-ldflags) $(objs) $(link-ldadd) $(libgcccore)

link-script-cppflags :=  \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinccore) $(CPPFLAGS) \
		$(addprefix -I,$(incdirscore)) $(cppflagscore))


-include $(link-script-dep)

$(link-script-pp): $(link-script) $(conf-file)
	@$(cmd-echo-silent) '  CPP     $@'
	@mkdir -p $(dir $@)
	$(q)$(CPPcore) -Wp,-P,-MT,$@,-MD,$(link-script-dep) \
		$(link-script-cppflags) $< > $@


$(link-out-dir)/tee.elf: $(objs) $(libdeps) $(link-script-pp)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LDcore) $(ldargs-tee.elf) -o $@

$(link-out-dir)/tee.dmp: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMPcore) -l -x -d $< > $@

$(link-out-dir)/tee.bin: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPYcore) -O binary $< $@

$(link-out-dir)/tee.symb_sizes: $(link-out-dir)/tee.elf
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)$(NMcore) --print-size --reverse-sort --size-sort $< > $@
