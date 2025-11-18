#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2025, Linaro Ltd.
#

import os
import subprocess
import argparse
import re
from github import Github


def parse_get_maintainer_output(output: str):
    """Parse get_maintainer.py output and return GitHub handles to notify.

    All entries are parsed, but handles listed for 'THE REST' are removed
    from the final notification set.
    """
    handles = set()
    the_rest_handles = set()

    for line in output.splitlines():
        handle_start = line.find("[@")
        handle_end = line.find("]", handle_start)
        if handle_start == -1 or handle_end == -1:
            continue
        handle = line[handle_start + 2:handle_end].strip()

        paren_start = line.find("(", handle_end)
        paren_end = line.rfind(")")
        target = None
        if paren_start != -1 and paren_end != -1:
            content = line[paren_start + 1:paren_end].strip()
            if ":" in content:
                _, target = content.split(":", 1)
                target = target.strip()

        if target and target.upper() == "THE REST":
            the_rest_handles.add(handle)
        else:
            handles.add(handle)

    allh = set()
    allh.update(handles)
    allh.update(the_rest_handles)

    if allh:
        print("For information: all relevant maintainers/reviewers: " +
              " ".join(f"@{h}" for h in allh))
    if handles:
        print("Subsystem/platform maintainers/reviewers: " +
              " ".join(f"@{h}" for h in handles))
    if the_rest_handles:
        print("Excluding handles from THE REST: " +
              " ".join(f"@{h}" for h in the_rest_handles))

    # Remove any handle that was marked as THE REST
    handles_to_mention = handles - the_rest_handles
    return handles_to_mention


def get_handles_for_pr(pr_number: str):
    """Run get_maintainer.py with -g PR_NUMBER and parse handles."""
    cmd = [
        os.path.join(os.getcwd(), "scripts/get_maintainer.py"),
        "-g", pr_number
    ]
    output = subprocess.check_output(cmd, text=True)
    return parse_get_maintainer_output(output)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Notify maintainers/reviewers for a PR using "
            "get_maintainer.py.\n"
            "If run in a GitHub environment (GITHUB_TOKEN and REPO set), "
            "the notification message is posted directly to the PR. "
            "Otherwise, the script outputs the message to the console.\n"
            "The message lists the GitHub handles of all reviewers and "
            "maintainers responsible for the modified files. Handles "
            "already mentioned in the PR are not repeated, nor are "
            "requested reviewers, assignees and maintainers for 'THE REST' "
        )
    )
    parser.add_argument(
        "--pr",
        help="GitHub PR number (required outside GitHub environment)."
    )
    args = parser.parse_args()

    github_env = all(os.getenv(var) for var in ("GITHUB_TOKEN", "REPO"))

    if github_env:
        pr_number = args.pr or os.getenv("PR_NUMBER")
        repo_name = os.getenv("REPO")
        token = os.getenv("GITHUB_TOKEN")
        if not pr_number:
            print(
                "Running in GitHub environment but no PR_NUMBER found. "
                "Doing nothing."
            )
            return
    else:
        pr_number = args.pr
        if not pr_number:
            print("Error: --pr must be provided outside GitHub environment.")
            return
        repo_name = None
        token = None

    handles_to_mention = get_handles_for_pr(pr_number)
    if not handles_to_mention:
        print("No maintainers or reviewers to mention.")
        return
    else:
        print("Final list of subsystem/platform maintainers/reviewers: " +
              " ".join(f"@{h}" for h in handles_to_mention))

    if github_env:
        g = Github(token)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(int(pr_number))

        # Gather existing handles mentioned in previous comments
        existing_handles = set()
        for comment in pr.get_issue_comments():
            existing_handles.update(re.findall(r"@([\w-]+)", comment.body))
        if existing_handles:
            print("Already mentioned: " +
                  " ".join(f"@{h}" for h in existing_handles))

        # Skip PR author, assignees, and requested reviewers
        skip_handles = {pr.user.login}
        skip_handles.update(a.login for a in pr.assignees)
        requested_reviewers, _ = pr.get_review_requests()
        skip_handles.update(r.login for r in requested_reviewers)
        if skip_handles:
            print("Excluding author, assignees and requested reviewers: " +
                  " ".join(f"@{h}" for h in skip_handles))

        # Exclude all these from new notifications
        new_handles = handles_to_mention - existing_handles - skip_handles
        if not new_handles:
            print("All relevant handles have already been mentioned "
                  "or are already notified by GitHub.")
            return

        message = ("FYI " + " ".join(f"@{h}" for h in new_handles))
        pr.create_issue_comment(message)
        print(f"Comment added to PR: '{message}'")
    else:
        message = ("FYI " + " ".join(f"@{h}" for h in handles_to_mention))
        print(f"Comment added to PR would be: '{message}'")


if __name__ == "__main__":
    main()
