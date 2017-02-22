#!/bin/bash

DIR="${BASH_SOURCE%/*}"

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
