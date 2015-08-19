#!/bin/bash

CHECKPATCH="${CHECKPATCH:-checkpatch.pl}"
# checkpatch.pl will ignore the following paths
CHECKPATCH_IGNORE=$(echo core/lib/lib{fdt,tomcrypt} lib/lib{png,utils,zlib} \
		core/arch/arm/plat-ti/api_monitor_index.h)
_CP_EXCL=$(for p in $CHECKPATCH_IGNORE; do echo ":(exclude)$p" ; done)

function _checkpatch() {
		$CHECKPATCH --quiet --ignore FILE_PATH_CHANGES \
				--ignore GERRIT_CHANGE_ID --no-tree -
}

function checkpatch() {
		git show --oneline --no-patch $1
		git format-patch -1 $1 --stdout -- $_CP_EXCL . | _checkpatch
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

