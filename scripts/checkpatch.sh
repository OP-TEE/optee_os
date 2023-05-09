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

help() {
  cat <<-EOF
Usage:
  checkpatch.sh [--working]
  checkpatch.sh <COMMIT>...
  checkpatch.sh <SELECTION>...
  checkpatch.sh --diff <COMMIT> <COMMIT>
  checkpatch.sh --cached
  checkpatch.sh --help

Args:
  <COMMIT>        Any commit or any number of commits.
  <SELECTION>     Any number of Git Revision Selections. (requires git v2.19)
                  https://git-scm.com/book/en/v2/Git-Tools-Revision-Selection

Options:
  --working                     Check the working area [Default].
  --cached                      Check the staging area.
  --diff <commit1> <commit2>    Check the diff between commit1 and commit2.
  --help                        Print this help message.

Examples:
  checkpatch.sh commit1 commit2 commit3   Check commit1, commit2, and commit3.

  checkpatch.sh HEAD~5                    Check the commit 5 revisions before
                                          the current HEAD.

  checkpatch.sh commit1..^commit2         Check each commit from commit1 to
                                          commit2 inclusively.
                                          (requires git v2.19)

  checkpatch.sh HEAD~5..HEAD~1            Check each commit from HEAD~5 to
                                          HEAD~1 exclusively, aka not including
                                          HEAD~1. (requires git v2.19)

  checkpatch.sh commit1...tags/tag1       Check each commit that exists
                                          exclusively within the history of
                                          only one of each given revision.
                                          (requires git v2.19)

  checkpatch.sh HEAD~10-5                 Check 5 commits moving forward in
                                          history starting from HEAD~10.
                                          (requires git v2.19)

  checkpatch.sh branch1 tags/tag1         Check the HEAD of branch1 and the
                                          HEAD of tag1. (requires git v2.19)
EOF
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
		help
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
