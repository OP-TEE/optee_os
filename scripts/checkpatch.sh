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
  echo "       $SCR <commit>...                 Check specific commits,
                                                symbolic names, and/or revision
                                                selections"
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
    read -r MAJOR MINOR < <(git --version | awk -F '[. ]' '{print $3, $4}')
    if (( MAJOR < 2 )) || (( MAJOR == 2 && MINOR < 19 )); then
      for c in "$@"; do checkpatch "$c"; done
    else
      for arg in "$@"; do
        # parse the argument into a git object or list of git objects
        object="$(git rev-parse "${arg}")" || continue
        # run checkpatch if the parsed argument represents a single commit hash
        if git cat-file -e "${object}" 2>/dev/null; then
          checkpatch "${object}"
        else
          # expand the object list and run checkpatch on each commit id
          commits="$(echo "${object}" | git rev-list --stdin)"
          for c in ${commits}; do checkpatch "$c"; done
        fi
      done
    fi
    ;;

esac
