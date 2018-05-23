.. SPDX-License-Identifier: BSD-2-Clause
.. _external_libraries:

==================
External libraries
==================

OP-TEE OS contains code imported from external libraries such as:

- LibTomCrypt_ in ``core/lib/libtomcrypt/``
- Newlib_ in ``lib/libutils/isoc/newlib/``
- `mbed TLS`_ in ``lib/libmbedtls/``

Historically and for convenience, the imported code was directly committed into
the OP-TEE source tree. Doing otherwise, such as using Git submodules, would
have made things more complex and error-prone for OP-TEE users and developers
and was not deemed necessary.

While this choice is good for smaller libraries or the ones that do not change
much, it can be problematic for larger libraries which need to be synchronized
with upstream occasionally, especially as local changes accumulate in the
library.

Therefore, this document defines a process that should hopefully help import
and maintain any substantial piece of external code into the OP-TEE Git.

mbed TLS version 2.6.1 is used as an example.

Importing code
--------------

1. An OP-TEE maintainer creates a branch: ``import/mbedtls-2.6.1`` from current
   ``master``.
2. A contributor creates a pull request against this branch, with the following
   commits (see `PR#2338`_ for the real example):

   - ``Import mbedtls-2.6.1``. This is the base commit which imports the code
     unmodified from the upstream project. Some files may be omitted but no
     other change is allowed. In the commit description, the upstream commit or
     tag should be clearly identified.
   - ``<Local change #1>``
   - ``<Local change #2>``... A number of local modifications should follow,
     typically some local adaptations to configuration and/or build files but
     possibly also some modifications that are needed so that OP-TEE may use
     the library. These local changes will be carried to newer versions of the
     imported library when needed.

3. The pull request is reviewed and merged normally (into the
   ``import/mbedtls-2.6.1`` branch).
4. The contributor creates a pull request against ``master`` which uses the
   imported library to add some feature. The pull request typically contains
   the following commits:

   - ``<Preparatory work>``...
   - ``Squashed commit importing mbedtls-2.6.1 source``. As the description
     suggests, this adds the contents committed in step 2 above as a single
     commit.
   - ``<Enable the new feature>``

5. The pull request is reviewed and merged normally.

Adding further local features or fixes to the imported library
--------------------------------------------------------------

Whenever a change has to be made locally to the imported library, the import
branch should be modified first. The steps are:

1. A contributor creates a pull request against the import branch:
   ``import/mbedtls-2.6.1``. It may happen that the proposed change depends on
   commits that are in master but not in the import branch, which would cause
   the CI to fail. In this case, it is desirable that the contributor asks a
   maintainer to **merge** (not rebase) ``optee_os master`` into the import
   branch. The history of the import branch can still be shown easily with
   ``git log --first-parent import/mbedtls-2.6.1``.
2. The pull request is reviewed and merged into the import branch.
3. The contributor creates a pull request against ``master``. The commits
   are cherry-picks of those that were merged into the import branch, plus
   any additional changes in ``optee_os`` that may be required.
4. The pull request is reviewed and merged into the master branch.

Updating the imported code to a newer upstream revision
------------------------------------------------------

When it is time to update the imported library, say to an hypothetic mbed TLS
version 2.6.2, a similar process is applied again:

1. An OP-TEE maintainter creates a branch: ``import/mbedtls-2.6.2`` from
   current ``master``.
2. A contributor creates a pull request against this new branch with the
   following patches:

   - ``Remove all files under lib/libmbedtls``
   - ``Import mbed TLS 2.6.2`` (some unneeded files may be omitted)
   - Cherry-pick all the patches from ``import/mbedtls-2.6.1`` (except ``Import
     mbedtls-2.6.1`` of course).

3. The pull request is reviewed and merged normally (into the
   ``import/mbedtls-2.6.2`` branch)
4. The contributor creates a pull request against master:

   - ``Squashed commit upgrading to mbedtls-2.6.2``. This is a squashed merge
     to master of the commits in the ``import/mbedtls-2.6.2`` branch.

5. The pull request is reviewed and merged normally.

.. _LibTomCrypt: https://github.com/libtom/libtomcrypt
.. _Newlib: https://sourceware.org/newlib/
.. _`mbed TLS`: https://tls.mbed.org/
.. _`PR#2338`: https://github.com/OP-TEE/optee_os/pull/2338
