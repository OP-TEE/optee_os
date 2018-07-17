subdirs-y += kernel
subdirs-y += crypto
subdirs-y += tee
subdirs-y += drivers

ifeq ($(CFG_WITH_USER_TA),y)
gensrcs-y += ta_pub_key
produce-ta_pub_key = ta_pub_key.c
depends-ta_pub_key = $(TA_SIGN_KEY) scripts/pem_to_pub_c.py
recipe-ta_pub_key = scripts/pem_to_pub_c.py --prefix ta_pub_key \
		--key $(TA_SIGN_KEY) --out $(sub-dir-out)/ta_pub_key.c
cleanfiles += $(sub-dir-out)/ta_pub_key.c
endif

ifeq ($(CFG_WITH_USER_TA)-$(CFG_EARLY_TA),y-y)
define process_early_ta
early-ta-$1-uuid := $(firstword $(subst ., ,$(notdir $1)))
gensrcs-y += early-ta-$1
produce-early-ta-$1 = early_ta_$$(early-ta-$1-uuid).c
depends-early-ta-$1 = $1 scripts/ta_bin_to_c.py
recipe-early-ta-$1 = scripts/ta_bin_to_c.py --compress --ta $1 \
		--out $(sub-dir-out)/early_ta_$$(early-ta-$1-uuid).c
cleanfiles += $(sub-dir-out)/early_ta_$$(early-ta-$1-uuid).c
endef
$(foreach f, $(EARLY_TA_PATHS), $(eval $(call process_early_ta,$(f))))
$(foreach f, $(CFG_IN_TREE_EARLY_TAS), $(eval $(call \
	process_early_ta,$(out-dir)/ta/$(f).stripped.elf)))
endif
