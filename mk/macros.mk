# Rename $1 to $2 only if file content differs. Otherwise just delete $1.
define mv-if-changed
	if cmp -s $2 $1; then					\
		rm -f $1;					\
	else							\
		$(cmd-echo-silent) '  UPD     $2';		\
		mv $1 $2;					\
	fi
endef
