#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019, Linaro Limited
#

from subprocess import Popen, PIPE
import argparse


def get_args():
    parser = argparse.ArgumentParser(description='Helper script that updates '
                                     'the CHANGELOG.md file.\n'
                                     'Usage example:\n'
                                     '  ./update_changelog.py '
                                     ' --changelog-file CHANGELOG.md'
                                     ' --release-version 3.7.0'
                                     ' --previous-release-version 3.6.0'
                                     ' --release-date 2019-10-11')

    parser.add_argument('--changelog-file', action='store', required=False,
                        default='CHANGELOG.md',
                        help='Changelog file to be updated.')

    parser.add_argument('--release-date', action='store', required=True,
                        help='The release date (yyyy-mm-dd).')

    parser.add_argument('--release-version', action='store', required=True,
                        help='Release version (MAJOR.MINOR.PATCH).')

    parser.add_argument('--previous-release-version', action='store',
                        required=True,
                        help='Previous release version (MAJOR.MINOR.PATCH).')

    return parser.parse_args()


def prepend_write(filename, text):
    with open(filename, 'r+') as f:
        current_content = f.read()
        f.seek(0, 0)
        f.write(text + '\n' + current_content)
        f.flush()


def get_previous_release_date(tag):
    cmd = "git log -1 --date=format:%Y-%m-%d --format=format:%cd " \
          "{}".format(tag)
    process = Popen(cmd.split(), stdout=PIPE)
    (output, err) = process.communicate()
    return output.decode("utf-8")


def main():
    global args

    args = get_args()

    gits = ["OP-TEE/optee_os", "OP-TEE/optee_client", "OP-TEE/optee_test",
            "OP-TEE/build", "linaro-swg/optee_examples"]

    # Shorten name
    clf = args.changelog_file
    rv = args.release_version
    prv = args.previous_release_version
    rd = args.release_date
    prd = get_previous_release_date(prv)

    # In some cases we need underscore in string
    rvu = rv.replace('.', '_')

    text = "# OP-TEE - version {} ({})\n".format(rv, rd)
    text += "\n"
    text += "- Links to the release pages, commits and pull requests merged " \
            "into this release for:\n"

    for g in gits:
        gu = g.replace('/', '_')
        gu = gu.replace('-', '_')
        text += "  - {}: [release page][{}_release_{}], " \
                "[commits][{}_commits_{}] and [pull requests]" \
                "[{}_pr_{}]\n".format(g, gu, rvu, gu, rvu, gu, rvu)

    text += "\n"

    for g in gits:
        gu = g.replace('/', '_')
        gu = gu.replace('-', '_')
        text += "\n[{}_release_{}]: https://github.com/{}/releases/tag/" \
                "{}\n".format(gu, rvu, g, rv)
        text += "[{}_commits_{}]: https://github.com/{}/compare/" \
                "{}...{}\n".format(gu, rvu, g, prv, rv)
        text += "[{}_pr_{}]: https://github.com/{}/pulls?q=is%3Apr+is%3A" \
                "merged+base%3Amaster+merged%3A{}..{}\n".format(
                        gu, rvu, g, prd, rd)

    prepend_write(args.changelog_file, text)


if __name__ == "__main__":
    main()
