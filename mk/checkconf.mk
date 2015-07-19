# Generate/check/update a .h file to reflect the values of Makefile
# variables
#
# Example usage (by default, check-conf-h will consider all CFG_*
# and _CFG_* variables):
#
# path/to/conf.h: FORCE
#	$(call check-conf-h)
#
# Or, to include only the variables with the given prefix(es):
#
# path/to/crypto_config.h: FORCE
#	$(call check-conf-h,CFG_CRYPTO_ CRYPTO_)
define check-conf-h
	$(q)set -e;						\
	$(cmd-echo-silent) '  CHK     $@';			\
	cnf="$(strip $(foreach var,				\
		$(call cfg-vars-by-prefix,$1),			\
		$(call cfg-make-define,$(var))))";		\
	guard="_`echo $@ | tr -- -/. ___`_";			\
	mkdir -p $(dir $@);					\
	echo "#ifndef $${guard}" >$@.tmp;			\
	echo "#define $${guard}" >>$@.tmp;			\
	echo -n "$${cnf}" | sed 's/_nl_ */\n/g' >>$@.tmp;	\
	echo "#endif" >>$@.tmp;					\
	$(call mv-if-changed,$@.tmp,$@)
endef

define check-conf-mk
	$(q)set -e;						\
	$(cmd-echo-silent) '  CHK     $@';			\
	cnf="$(strip $(foreach var,				\
		$(call cfg-vars-by-prefix,CFG_),		\
		$(call cfg-make-variable,$(var))))";		\
	mkdir -p $(dir $@);					\
	echo "# auto-generated TEE configuration file" >$@.tmp; \
	echo "# TEE version $${CFG_TEE_VERSION:-(undefined)}" >>$@.tmp; \
	echo "ARCH=${ARCH}" >>$@.tmp;				\
	echo "PLATFORM=${PLATFORM}" >>$@.tmp;			\
	echo "PLATFORM_FLAVOR=${PLATFORM_FLAVOR}" >>$@.tmp; 	\
	echo -n "$${cnf}" | sed 's/_nl_ */\n/g' >>$@.tmp;	\
	$(call mv-if-changed,$@.tmp,$@)
endef

# Rename $1 to $2 only if file content differs. Otherwise just delete $1.
define mv-if-changed
	if [ -r $2 ] && cmp -s $2 $1; then			\
		rm -f $1;					\
	else							\
		$(cmd-echo-silent) '  UPD     $2';		\
		mv $1 $2;					\
	fi
endef

define cfg-vars-by-prefix
	$(strip $(if $(1),$(call _cfg-vars-by-prefix,$(1)),
			  $(call _cfg-vars-by-prefix,CFG_ _CFG_)))
endef

define _cfg-vars-by-prefix
	$(sort $(foreach prefix,$(1),$(filter $(prefix)%,$(.VARIABLES))))
endef

# Convert a makefile variable to a #define
# <undefined>, n => <undefined>
# y              => 1
# <other value>  => <other value>
define cfg-make-define
	$(strip $(if $(filter y,$($1)),
		     #define $1 1 /* '$($1)' */_nl_,
		     $(if $(filter xn x,x$($1)),
			  /* $1 is not set ('$($1)') */_nl_,
			  #define $1 $($1) /* '$($1)' */_nl_)))
endef

define cfg-make-variable
	$(strip $(if $(filter xn x,x$($1)),
			  # $1 is not set ('$($1)')_nl_,
			  $1=$($1)_nl_))
endef

# Returns 'y' if at least one variable is 'y', empty otherwise
# Example:
# FOO_OR_BAR := $(call cfg-one-enabled, FOO BAR)
cfg-one-enabled = $(if $(filter y, $(foreach var,$(1),$($(var)))),y,)

# Returns 'y' if all variables are 'y', empty otherwise
# Example:
# FOO_AND_BAR := $(call cfg-all-enabled, FOO BAR)
cfg-all-enabled =                                                             \
    $(strip                                                                   \
        $(if $(1),                                                            \
            $(if $(filter y,$($(firstword $(1)))),                            \
                $(call cfg-all-enabled,$(filter-out $(firstword $(1)),$(1))), \
             ),                                                               \
            y                                                                 \
         )                                                                    \
     )

# Disable a configuration variable if some dependency is disabled
# Example:
# $(eval $(call cfg-depends-all,FOO,BAR BAZ))
# Will clear FOO if it is initially 'y' and BAR or BAZ are not 'y'
cfg-depends-all =                                                           \
    $(strip                                                                 \
        $(if $(filter y, $($(1))),                                          \
            $(if $(call cfg-all-enabled,$(2)),                              \
                ,                                                           \
                $(warning Warning: Disabling $(1) [requires $(strip $(2))]) \
                    override $(1) :=                                        \
             )                                                              \
         )                                                                  \
     )

# Disable a configuration variable if all dependencies are disabled
# Example:
# $(eval $(call cfg-depends-one,FOO,BAR BAZ))
# Will clear FOO if it is initially 'y' and both BAR and BAZ are not 'y'
cfg-depends-one =                                                                    \
    $(strip                                                                          \
        $(if $(filter y, $($(1))),                                                   \
            $(if $(call cfg-one-enabled,$(2)),                                       \
                ,                                                                    \
                $(warning Warning: Disabling $(1) [requires (one of) $(strip $(2))]) \
                    override $(1) :=                                                 \
             )                                                                       \
         )                                                                           \
     )


# Enable all depend variables
# Example:
# $(eval $(call cfg-enable-all-depends,FOO,BAR BAZ))
# Will enable BAR and BAZ if FOO is initially 'y'
cfg-enable-all-depends =                                                                   \
    $(strip                                                                                \
        $(if $(2),                                                                         \
            $(if $(filter y, $($(1))),                                                     \
                $(if $(filter y,$($(firstword $(2)))),                                     \
                    ,                                                                      \
                    $(warning Warning: Enabling $(firstword $(2)) [required by $(1)])      \
                        $(eval $(firstword $(2)) = y)                                      \
                 )                                                                         \
                 $(call cfg-enable-all-depends,$(1),$(filter-out $(firstword $(2)),$(2))), \
             )                                                                             \
             ,                                                                             \
        )                                                                                  \
     )
