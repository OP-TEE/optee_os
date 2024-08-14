# Rename $1 to $2 only if file content differs. Otherwise just delete $1.
define mv-if-changed
	if cmp -s $2 $1; then					\
		rm -f $1;					\
	else							\
		$(cmd-echo-silent) '  UPD     $2';		\
		mv $1 $2;					\
	fi
endef

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
version-o-cflags = $(filter-out -g3,$(CFLAGS) $(core-platform-cflags) \
			$(platform-cflags) $(cflagscore))
# SOURCE_DATE_EPOCH defined for reproducible builds
ifneq ($(SOURCE_DATE_EPOCH),)
date-opts = -d @$(SOURCE_DATE_EPOCH)
endif
DATE_STR = `LC_ALL=C date -u $(date-opts)`
CORE_CC_VERSION = `$(CCcore) -v 2>&1 | grep "version " | sed 's/ *$$//'`
define gen-version-o
	$(call update-buildcount,$(link-out-dir)/.buildcount)
	@$(cmd-echo-silent) '  GEN     $(link-out-dir)/version.o'
	$(q)cd $(link-out-dir) && \
		BUILD_COUNT_STR=`cat .buildcount` && \
		echo -e "const char core_v_str[] =" \
		"\"$(TEE_IMPL_VERSION) \"" \
		"\"($(CORE_CC_VERSION)) \"" \
		"\"#$${BUILD_COUNT_STR} \"" \
		"\"$(DATE_STR) \"" \
		"\"$(CFG_KERN_LINKER_ARCH)\";\n" \
		| $(CCcore) $(version-o-cflags) \
			-xc - -c -o version.o
endef
