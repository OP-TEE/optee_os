#!/bin/bash

DIR="${BASH_SOURCE%/*}"

# if no CHECKPATCH is explicitly given by the environment, try to
# locate checkpatch.pl: first take the one from the path, then check
# for a local copy of the linux headers, finally try sources downloaded
# with OP-TEE (for QEMU)
if [ -z "$CHECKPATCH" ]; then
  CHECKPATCH=$(command -v checkpatch.pl)
fi
if [ -z "$CHECKPATCH" ]; then
  CHECKPATCH=$(find /usr/src/linux-headers* -name checkpatch.pl -print -quit)
fi
if [ -z "$CHECKPATCH" ]; then
  CHECKPATCH=$(find "$PWD/../linux" -name checkpatch.pl -print -quit)
fi

source "$DIR/checkpatch_inc.sh"

hash $CHECKPATCH 2>/dev/null ||
		{ echo >&2 "Could not find checkpatch.pl, aborting"; exit 1; }

usage() {
  SCR=$(basename "$0")
  echo "Usage: $SCR [--working]                 Check working area"
  echo "       $SCR <commit>...                 Check specific commit(s)"
  echo "       $SCR --diff <commit1> <commit2>  Check diff commit1...commit2"
  echo "       $SCR --cached                    Check staging area"
  echo "       $SCR --help                      This help"
  exit 1
}

op=${1:---working}
case "$op" in
	--cached)
		echo "Checking staging area:  "
		checkstaging
		;;
	--diff)
		echo "Checking diff (diff $1...$2)"
		checkdiff "$2" "$3"
		;;
	--working)
		echo "Checking working area:  "
		checkworking
		;;
	--help|-h)
		usage
		;;
	*)
		echo "Checking commit(s):"
		for c in $*; do checkpatch $c; done
		;;

esac
