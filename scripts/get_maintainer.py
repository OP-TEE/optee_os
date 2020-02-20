#!/usr/bin/env python3
#
# Copyright (c) 2019, Linaro Limited
#
# SPDX-License-Identifier: BSD-2-Clause

from pathlib import PurePath
from urllib.request import urlopen

import argparse
import glob
import os
import re
import tempfile


DIFF_GIT_RE = re.compile(r'^diff --git a/(?P<path>.*) ')
REVIEWED_RE = re.compile(r'^Reviewed-by: (?P<approver>.*>)')
ACKED_RE = re.compile(r'^Acked-by: (?P<approver>.*>)')
PATCH_START = re.compile(r'^From [0-9a-f]{40}')


def get_args():
    parser = argparse.ArgumentParser(description='Print the maintainers for '
                                     'the given source files or directories; '
                                     'or for the files modified by a patch or '
                                     'a pull request. '
                                     '(With -m) Check if a patch or pull '
                                     'request is properly Acked/Reviewed for '
                                     'merging.')
    parser.add_argument('-m', '--merge-check', action='store_true',
                        help='use Reviewed-by: and Acked-by: tags found in '
                        'patches to prevent display of information for all '
                        'the approved paths.')
    parser.add_argument('-p', '--show-paths', action='store_true',
                        help='show all paths that are not approved.')
    parser.add_argument('-s', '--strict', action='store_true',
                        help='stricter conditions for patch approval check: '
                        'subsystem "THE REST" is ignored for paths that '
                        'match some other subsystem.')
    parser.add_argument('arg', nargs='*', help='file or patch')
    parser.add_argument('-f', '--file', action='append',
                        help='treat following argument as a file path, not '
                        'a patch.')
    parser.add_argument('-g', '--github-pr', action='append', type=int,
                        help='Github pull request ID. The script will '
                        'download the patchset from Github to a temporary '
                        'file and process it.')
    parser.add_argument('-r', '--release-to', action='store_true',
                        help='show all the recipients to be used in release '
                        'announcement emails (i.e., maintainers and reviewers)'
                        'and exit.')
    return parser.parse_args()


def check_cwd():
    cwd = os.getcwd()
    parent = os.path.dirname(os.path.realpath(__file__)) + "/../"
    if (os.path.realpath(cwd) != os.path.realpath(parent)):
        print("Error: this script must be run from the top-level of the "
              "optee_os tree")
        exit(1)


# Parse MAINTAINERS and return a dictionary of subsystems such as:
# {'Subsystem name': {'R': ['foo', 'bar'], 'S': ['Maintained'],
#                     'F': [ 'path1', 'path2' ]}, ...}
def parse_maintainers():
    subsystems = {}
    check_cwd()
    with open("MAINTAINERS", "r") as f:
        start_found = False
        ss = {}
        name = ''
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not start_found:
                if line.startswith("----------"):
                    start_found = True
                continue

            if line[1] == ':':
                letter = line[0]
                if (not ss.get(letter)):
                    ss[letter] = []
                ss[letter].append(line[3:])
            else:
                if name:
                    subsystems[name] = ss
                name = line
                ss = {}
        if name:
            subsystems[name] = ss

    return subsystems


# If @patchset is a patchset files and contains 2 patches or more, write
# individual patches to temporary files and return the paths.
# Otherwise return [].
def split_patchset(patchset):
    psname = os.path.basename(patchset).replace('.', '_')
    patchnum = 0
    of = None
    ret = []
    f = None
    try:
        f = open(patchset, "r")
    except OSError:
        return []
    for line in f:
        match = re.search(PATCH_START, line)
        if match:
            # New patch found: create new file
            patchnum += 1
            prefix = "{}_{}_".format(patchnum, psname)
            of = tempfile.NamedTemporaryFile(mode="w", prefix=prefix,
                                             suffix=".patch",
                                             delete=False)
            ret.append(of.name)
        if of:
            of.write(line)
    if len(ret) >= 2:
        return ret
    if len(ret) == 1:
        os.remove(ret[0])
    return []


# If @path is a patch file, returns the paths touched by the patch as well
# as the content of the review/ack tags
def get_paths_from_patch(patch):
    paths = []
    approvers = []
    try:
        with open(patch, "r") as f:
            for line in f:
                match = re.search(DIFF_GIT_RE, line)
                if match:
                    p = match.group('path')
                    if p not in paths:
                        paths.append(p)
                    continue
                match = re.search(REVIEWED_RE, line)
                if match:
                    a = match.group('approver')
                    if a not in approvers:
                        approvers.append(a)
                    continue
                match = re.search(ACKED_RE, line)
                if match:
                    a = match.group('approver')
                    if a not in approvers:
                        approvers.append(a)
                    continue
    except Exception:
        pass
    return (paths, approvers)


# Does @path match @pattern?
# @pattern has the syntax defined in the Linux MAINTAINERS file -- mostly a
# shell glob pattern, except that a trailing slash means a directory and
# everything below. Matching can easily be done by converting to a regexp.
def match_pattern(path, pattern):
    # Append a trailing slash if path is an existing directory, so that it
    # matches F: entries such as 'foo/bar/'
    if not path.endswith('/') and os.path.isdir(path):
        path += '/'
    rep = "^" + pattern
    rep = rep.replace('*', '[^/]+')
    rep = rep.replace('?', '[^/]')
    if rep.endswith('/'):
        rep += '.*'
    rep += '$'
    return not not re.match(rep, path)


def get_subsystems_for_path(subsystems, path, strict):
    found = {}
    for key in subsystems:
        def inner():
            excluded = subsystems[key].get('X')
            if excluded:
                for pattern in excluded:
                    if match_pattern(path, pattern):
                        return  # next key
            included = subsystems[key].get('F')
            if not included:
                return  # next key
            for pattern in included:
                if match_pattern(path, pattern):
                    found[key] = subsystems[key]
        inner()
    if strict and len(found) > 1:
        found.pop('THE REST', None)
    return found


def get_ss_maintainers(subsys):
    return subsys.get('M') or []


def get_ss_reviewers(subsys):
    return subsys.get('R') or []


def get_ss_approvers(ss):
    return get_ss_maintainers(ss) + get_ss_reviewers(ss)


def approvers_have_approved(approved_by, approvers):
    for n in approvers:
        # Ignore anything after the email (Github ID...)
        n = n.split('>', 1)[0]
        for m in approved_by:
            m = m.split('>', 1)[0]
            if n == m:
                return True
    return False


def download(pr):
    url = "https://github.com/OP-TEE/optee_os/pull/{}.patch".format(pr)
    f = tempfile.NamedTemporaryFile(mode="wb", prefix="pr{}_".format(pr),
                                    suffix=".patch", delete=False)
    print("Downloading {}...".format(url), end='', flush=True)
    f.write(urlopen(url).read())
    print(" Done.")
    return f.name


def show_release_to():
    check_cwd()
    with open("MAINTAINERS", "r") as f:
        emails = sorted(set(re.findall(r'[RM]:\t(.*[\w]*<[\w\.-]+@[\w\.-]+>)',
                                       f.read())))
    print(*emails, sep=', ')


def main():
    global args

    args = get_args()

    if args.release_to:
        show_release_to()
        return

    all_subsystems = parse_maintainers()
    paths = []
    arglist = []
    downloads = []
    split_patches = []

    for pr in args.github_pr or []:
        downloads += [download(pr)]

    for arg in args.arg + downloads:
        if os.path.exists(arg):
            patches = split_patchset(arg)
            if patches:
                split_patches += patches
                continue
        arglist.append(arg)

    for arg in arglist + split_patches:
        patch_paths = []
        approved_by = []
        if os.path.exists(arg):
            # Try to parse as a patch
            (patch_paths, approved_by) = get_paths_from_patch(arg)
        if not patch_paths:
            # Not a patch, consider the path itself
            # as_posix() cleans the path a little bit (suppress leading ./ and
            # duplicate slashes...)
            patch_paths = [PurePath(arg).as_posix()]
        for path in patch_paths:
            approved = False
            if args.merge_check:
                ss_for_path = get_subsystems_for_path(all_subsystems, path,
                                                      args.strict)
                for key in ss_for_path:
                    ss_approvers = get_ss_approvers(ss_for_path[key])
                    if approvers_have_approved(approved_by, ss_approvers):
                        approved = True
            if not approved:
                paths += [path]

    for f in downloads + split_patches:
        os.remove(f)

    if args.file:
        paths += args.file

    if (args.show_paths):
        print(paths)

    ss = {}
    for path in paths:
        ss.update(get_subsystems_for_path(all_subsystems, path, args.strict))
    for key in ss:
        ss_name = key[:50] + (key[50:] and '...')
        for name in ss[key].get('M') or []:
            print("{} (maintainer:{})".format(name, ss_name))
        for name in ss[key].get('R') or []:
            print("{} (reviewer:{})".format(name, ss_name))


if __name__ == "__main__":
    main()
