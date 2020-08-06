#!/bin/bash

CHECKPATCH="${CHECKPATCH:-checkpatch.pl}"
# checkpatch.pl will ignore the following paths
CHECKPATCH_IGNORE=$(echo \
		core/include/gen-asm-defines.h \
		core/lib/lib{fdt,tomcrypt} core/lib/zlib \
		lib/libutils lib/libmbedtls \
		lib/libutee/include/elf.h \
		core/arch/arm/include/arm{32,64}.h \
		core/arch/arm/plat-ti/api_monitor_index_a{9,15}.h \
		core/arch/arm/dts)
_CP_EXCL=$(for p in $CHECKPATCH_IGNORE; do echo ":(exclude)$p" ; done)

function _checkpatch() {
		# Use --typedefsfile if supported by the checkpatch tool
		typedefs_opt="--typedefsfile typedefs.checkpatch"
		$CHECKPATCH --help 2>&1 | grep -q -- --typedefsfile || \
				typedefs_opt="";
		# Ignore NOT_UNIFIED_DIFF in case patch has no diff
		# (e.g., all paths filtered out)
		$CHECKPATCH $typedefs_opt -
}

function checkpatch() {
	git show --oneline --no-patch $1
	# The first git 'format-patch' shows the commit message
	# The second one produces the diff (might be empty if _CP_EXCL
	# filters out all diffs)
	(git format-patch $1^..$1 --stdout | sed -n '/^diff --git/q;p'; \
	 git format-patch $1^..$1 --stdout -- $_CP_EXCL . | \
		sed -n '/^diff --git/,$p') | _checkpatch
}

function checkstaging() {
		git diff --cached -- . $_CP_EXCL | _checkpatch
}

function checkworking() {
		git diff -- . $_CP_EXCL | _checkpatch
}

function checkdiff() {
		git diff $1...$2 -- . $_CP_EXCL | _checkpatch
}

