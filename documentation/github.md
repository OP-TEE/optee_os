GitHub usage
============

The document describes how to use GitHub. Various links to GitHub
documentation are given. The main GitHub  documentation is located
at <a href="https://help.github.com/">https://help.github.com/</a>


-----------------------------------------------------------------


GitHub Setup
------------

### GitHub Account Setup

In order to clone a repository, there is no need to own a GitHub
account. But as soon as one wants to contribute, a GitHub account
is required. In such a case, you must create a GitHub account
by connecting to
<a href="https://github.com/">https://github.com/</a>.
Click on *Sign up for GitHub* and follow the steps.
Note that a free plan is sufficient to collaborate to the project.

SSH connection with GitHub repositories is the way of developing that
is described in this help. For this, SSH keys must be configured as
described in the *ssh* section of
<a href="https://help.github.com/">https://help.github.com/</a>.


### Fork

Only owners of the OP-TEE repositories can write directly to the git
repositories. Contributors must *fork* the OP-TEE/optee_os.git repository
into their personal account to work. The complete documentation about *forking*
can be found at
<a href="https://help.github.com/articles/fork-a-repo">https://help.github.com/articles/fork-a-repo</a>.

Note that the fork has to be performed once and only once.


-----------------------------------------------------------------


Contributing
------------
In the following:

* Only the Linux commands to extract the sources and to
  contribute are given. Windows or iMac way of working are not described.
* *myaccount* stands for the developer github account id

### SSH Configuration
.ssh/config file may contain something like:

	Host github.com
	  user myaccount
	  IdentityFile ~/.ssh/id_rsa_github
	  Hostname 192.30.252.128

### Cloning the sources
	# Clone the forked repository
	git clone git@github.com:myaccount/optee_os.git

	# Add the reference, called "upstream"
	cd optee_os
	git remote add upstream git@github.com:OP-TEE/optee_os.git

	# Retrieve the gits
	git fetch --all

In order to be able to read the pull-request, one may add
in .git/config the following section

     # Add to manage Pull-Request
     [remote "upstream"]
         fetch = +refs/pull/*/head:refs/remotes/upstream/pr/*

Once retrieve, remotes/upstream/pr/* branches are appearing. They
correspond to the pull-request id code. Note that these branches
are read-only, for developers and owners. Have a look at
<a href="https://gist.github.com/piscisaureus/3342247">https://gist.github.com/piscisaureus/3342247</a>
for a complete description of this syntax.

Another way to pull a pull-request, without modifying .git/config file,
is to use the patch file that is available for each pull-request. As an
example, here is the command to pull the pull-request id #784:

    curl -L 'https://github.com/OP-TEE/optee_os/pull/784.patch' | git am

### Synchronization

First of all, the forked repository must be in sync with the OP-TEE
sources. Let's assume that *upstream_master* is the local branch corresponding to *remotes/upstream/master*

Synchronizing the forked and the upstream repositories can be done through

	# Update the local sources
	git fetch --all

	# Reset upstream_master
	git checkout upstream_master
	git reset --hard upstream/master
	git push origin upstream_master:master

### Contributing

To be able to contribute, you must create a local branch containing your fixes.
The branch name must be explicit. Here are some examples:

* issue/75 if the contribution is expected to fix issue number 75.
* feature/more_traces if the contribution will add new traces
* ...

Here is how to create the contribute and push on the forked repository

	git checkout -b feature/my_new_feature
	... contribution ...
	git add .
	git commit -s

Commit message should be clear and as much explicit as possible.
Moreover, if the fix is related to the issue number 75 (as an example),
you must add in the commit message

	It fixes #75 (GitHub issue)

Then the contribution is pushed on the forked repository

	git push origin feature/my_new_feature:feature/my_new_feature

Then the pull-request can be created through the GitHub UI. Documentation
can be found at
<a href="https://help.github.com/articles/using-pull-requests">https://help.github.com/articles/using-pull-requests</a>
and the *Collaborating* section of
<a href="https://help.github.com">https://help.github.com</a>

It may be that you will get comments from reviewers on the commits you provided.
If so happens, you will need to address the comments and you might end up having
to upload additional commits, which could be done by the following commands

	git add .
	git commit -s
	git push origin feature/my_new_feature:feature/my_new_feature

Note that the pull-request is automatically updated with the new commit.

### Finalizing the contribution
Once reviewers and the contributor has agreed that the patch-set is OK, then the
contributor needs to squash the commits into a single commit (a
*"squashed-commit-on-top-of-master"*), meaning

* A single-point contribution for most of the cases
* That is rebased on upstream/master, in case the master has
  been updated
* Add tags in the commit message to grant people that reviewed and tested the patch.
  Typically, you may add at the end of the commit message the tags *Reviewed-by*
  and *Tested-by*, as provided in the comments of the pull-request.


Following commands are guidelines to achieve the
*squashed-commit-on-top-of-master*. Note that this ends with a
*"push -f"*

	git fetch --all
	git checkout -b feature/my_new_feature_tbs
	git checkout feature/my_new_feature
	git reset --hard upstream/master
	git merge --squash feature/my_new_feature_tbs
	git commit -s
		(add the tag, as for example):
		Reviewed-by: Jerome Forissier <jerome.forissier@linaro.org>
		Reviewed-by: Jens Wiklander <jens.wiklander@linaro.org>
		Tested-by: Joakim Bech <joakim.bech@linaro.org> (FVP platform)
		Tested-by: Pascal Brand <pascal.brand@linaro.org> (STM platform)
	git push -f origin feature/my_new_feature:feature/my_new_feature

Note:

* The commit message may take a summary of all the squashed
  commit messages. Also, one should add which GitHub issue it fixes,
  if any.
* Some comments created in the GitHub UI will be lost.

The owner of OP-TEE/optee_os.git can now merge the pull-request.
How this is done is not described in this document.
It is the owners responsibility to save a log of the comments that were
available before the forced-push.
