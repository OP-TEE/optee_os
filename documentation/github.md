GitHub usage
============

This document describes how to use GitHub for OP-TEE development and
contributions.


GitHub Setup
------------

### Setting up an account

You do not need to own a GitHub account in order to clone a repository. But if
you want to contribute, you need to create an account at
[github.com](https://github.com) first. Note that a free plan is sufficient to
collaborate.

SSH is recommended to access your GitHub repositories securely and without
supplying your username and password each time you pull or push something.
To configure SSH for GitHub, please refer to [Connecting to GitHub with SSH](
https://help.github.com/articles/connecting-to-github-with-ssh/).

### Forking

Only owners of the OP-TEE projects have write permission to the Git
repositories of those projects. Contributors should *fork*
`OP-TEE/optee_os.git` into their own account, then work on this forked
repository. The complete documentation about *forking* can be found at
[Fork A Repo](https://help.github.com/articles/fork-a-repo).

Note that the fork only has to be performed once.

Contributing
------------
In the following:

* *myaccount* stands for the name of your GitHub account.
* It is assumed you have configured SSH keys so that the `git` command can
fetch and push code to your GitHub repositories. Otherwise, your GitHub
credentials (email address and password) will be asked for each `git push`
command.

### Cloning the sources

To obtain a local copy of your `optee_os` project, do:

    # Clone the forked repository
    git clone git@github.com:myaccount/optee_os

    # Add a remote called "upstream" which is the official OP-TEE Git
    cd optee_os
    git remote add upstream https://github.com/OP-TEE/optee_os

    # Retrieve the gits
    git fetch --all

The above steps are enough to be able to build OP-TEE OS, make some changes,
and optionally publish (or "push") them to your GitHub account.
Pushing commits to your account allows you to later create "pull requests"
against the official OP-TEE repository (called "upstream"), if you would
like to contribute your changes back to the project.

However, please note that [optee_os](https://github.com/OP-TEE/optee_os]) is
only a fraction of the software needed to run an OP-TEE environment. As such,
OP-TEE developers typically have to deal with a forest of Git trees including
[optee_client](https://github.com/OP-TEE/optee_client]), the Linux kernel,
ARM Trusted Firmware, test applications and other things. For this reason, it
is recommended that you check the
[OP-TEE build project](https://github.com/OP-TEE/build). This project contains
the complete source code required to build working OP-TEE environments for
several platforms. You may then apply the instructions given here to the
`optee_os` repository that is checked out as a part of the main project. Some
adjustments will be needed, though, because of the way the `repo` tool sets up
the Git repositories.

### Contributing

The typical workflow to make a change to the OP-TEE OS code and push it to
your GitHub account is as follows.

    # Update your local references to upstream branches
    git fetch upstream
    # Switch to the local master branch
    git checkout master
    # Update with the latest commits from upstream
    # WARNING: this command will lose any work you may have committed
    # on your local "master" branch or may have in your working area.
    # (In this work flow it is assumed local master is only ever used as a
    # copy of upstream master)
    git reset --hard upstream/master
    # Create a feature branch to receive your changes, based on master
    git checkout -b my_new_feature
    ... Code, build, test, debug, repeat ...
    ... Stage your changes with git add and/or git rm etc. ...
    # Commit your changes locally (-s adds your Signed-off-by: tag)
    git commit -s

We expect commit messages to mostly follow the [Linux kernel recommendations](
https://www.kernel.org/doc/Documentation/process/submitting-patches.rst).
Please use the output of `git log` in the `optee_os` repository  as a source of
inspiration. The important points are:

- The subject line should explain *what* the patch does as precisely as
possible. It is usually prefixed with keywords indicating which part of the
code is affected, but not always. Avoid lines longer than 80 characters.
- The commit description should give more details on *what* is changed, and
explain *why* it is done. Indication on how to enable and use some particular
feature can be useful, too. Try to limit line length to 72 characters, except
when pasting some error message (compiler diagnostic etc.). Long lines are
allowed to accommodate URLs, too (preferably use URLs in a Fixes: or Link:
tag).
- The commit message must end with a blank line followed by some tags,
including your sign-off:

        Signed-off-by: Your Name <your.email@some.domain>

  By applying such a tag to your commit, you are effectively declaring that your
contribution follows the terms stated by
[Notice - Contributions](../Notice.md#contributions). Other tags may follow,
such as:

        Fixes: <some bug URL>
        Fixes: 0123456789ab ("Some commit subject")
        Link: <some useful URL>

- When citing a previous commit, whether in the text body or in a Fixes: tag,
always use the format shown above (12 hexadecimal digits prefix of the commit
SHA1, followed by the commit subject in double quotes and parentheses).

Always split your changes into logical steps and create one commit for each
step.

Then the contribution is pushed on the forked repository with:

    git push

The pull-request can be created through the GitHub interface. Documentation
can be found at
[Using Pull Requests](https://help.github.com/articles/using-pull-requests) and
the *Collaborating* section of [help.github.com](https://help.github.com<).

It may be that you will get comments from reviewers on the commit(s) you provided.
If so happens, you will need to address the comments and you might end up having
to upload additional commits. If possible, create one or several fixup commit for
each initial commit that has to be changed. Doing so makes it easier for
reviewers to see what has changed and also for you when it is time to squash
commits (see below). The steps are:

    ... Address comments ...
    ... git add / git remove ...
    # Commit your updates locally
    git commit -s

If your changes are related to one initial commit, use the following subject:

    [Review] <Commit subject of the commit that is fixed by this one>

...and give a quick description of what is being addressed if it is not
obvious. Note that you are expected to include your `Signed-off-by:` to those
fixup commits, too. You may use some other prefix than `[Review]`, it does not
matter much, but just make it clear you are updating a previous commit, and
which one it is.

Once you are happy with your changes, and think all review comments have been
addressed (either by a followup commit or by replying to the comment on GitHub)
then you are ready to push your updates:

    git push

The pull request is automatically updated with the new commit(s) and reviewers
are notified, too.

### Finalizing your contribution

Once you and reviewers have agreed on the patch set, which is when all the
people who have commented on the pull request have given their `Acked-by:` or
`Reviewed-by:`, you need to consolidate your commits:

Use `git rebase -i` to squash the fixup commits (if any) into the initial
ones. For instance, suppose the `git log --oneline` for you contribution looks
as follows when the review process ends:

    <commit1> Do something
    <commit2> Do something else
    <commit3> [Review] Do something
    <commit4> [Review] Do something

Then you would do:

    git rebase -i <commit1>^
    # Edit the commit script so it looks like so:
    pick <commit1> Do something
    squash <commit3> [Review] Do something
    squash <commit4> [Review] Do something
    pick <commit2> Do something else

Add the proper tags (`Acked-by: ...`, `Reviewed-by: ...`, `Tested-by: ...`) to
the commit message(s), as provided by the people who reviewed and/or tested the
patches.

If you are not familiar with Git's interactive rebase feature, please read the
documentation at [Git Tools - Rewriting History](
https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History). Sections
*Changing Multiple Commit Messages*, *Reordering Commits* and *Squashing
Commits* are relevant to the current discussion.

Once `rebase -i` is done, you need to force-push (`-f`) to your GitHub branch
in order to update the pull request page.

    git push -f

At this point, it is the project maintainer's job to apply your patches to the
master branch.
