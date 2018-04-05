OP-TEE
=======

This is the repository of OP-TEE (Open Portable Trusted Execution Environment),
the open-source TEE maintained by Linaro, with initial contributions from
STMicroelectronics, Ericsson and Linaro Limited.

What OP-TEE is
-------

OP-TEE is a Trusted Execution Environment designed as companion to a non-secure
Linux kernel running on ARM&reg; Cortex-A cores using the TrustZone&reg;
technology. OP-TEE meets the TEE System Architecture and provides the TEE
Internal Core API v1.1 to Trusted Applications and the TEE Client API
v1.0, all as defined by the [GlobalPlatform TEE specifications].

The non-secure OS is referred to as the Rich Execution Environment (REE) in TEE
specifications. It is typically a Linux OS flavor as a GNU/Linux distribution
or the AOSP.

OP-TEE is designed primarily to rely on the ARM TrustZone technology as
the underlying hardware isolation mechanism. However, it has been structured
to be compatible with any isolation technology suitable for the TEE concept and
goals, such as running as a virtual machine or on a dedicated CPU.

The main design goals for OP-TEE are:
-	Isolation - the TEE provides isolation from the non-secure OS and
	protects the loaded Trusted Applications (TAs) from each other using
	underlying HW support,
-	Small footprint - the TEE should remain small enough to
	reside in a reasonable amount of on-chip memory as found on ARM
	based systems,
-	Portability - the TEE aims at being easily pluggable to different
	architectures and available HW and has to support various setups
	such as multiple client OSes or multiple TEEs.


Repository structure
------

OP-TEE comes with several components:
-	a secure privileged layer, executing at ARM secure PL-1 level,
-	a set of secure userland libraries designed for Trusted Applications
	needs,
-	a Linux kernel driver merged since v4.12,
-	a Linux userland library designed upon the GPD TEE Client API
	specifications
-	a Linux userland supplicant application for remote services expected by
	the TEE OS,
-	and some build scripts, debugging tools and examples to ease its
	integration and the development of trusted applications and secure
	services.

These components are available from several git repositories. The main ones are
the [optee_os], the [optee_client] and the [Linux kernel] since v4.12.

The [optee_os] git repository contains the source code for the TEE OS itself.
It includes the secure privileged layer hosting the Trusted Applications and
libraries complying with the TEE Internal Core API v1.1. It is distributed mostly
under the [BSD 2-Clause] open-source license. It includes few external files under
[BSD 3-Clause] license or other free software licenses.

The [optee_client] git repository contains the source code for the TEE client
library in a Linux OS providing the TEE Client API v1.0. It is distributed under
the [BSD 2-Clause] open-source license.

The [Linux kernel] contains the source code for the OP-TEE Linux driver. It is
distributed under the [GPLv2] open-source license.

There are other OP-TEE components one might be interested in. The OP-TEE release tag
references several git repositories enabling OP-TEE build and test for various
platforms. Refer to the [build documentation] for information. The [optee_test] git
repository proposes test materials through the `xtest` tool and dedicated trusted
applications. The [optee_examples] git repository contains examples of TEE client
and trusted applications and some documentation to get hands on trusted
application development.

Documentation
------
Documentation on design, implementation and tools can be found in
[optee_os/documentation](optee_os/documentation).

Contributions
------

Contributions to OP-TEE are managed by the OP-TEE gatekeepers, whose contact
email is op-tee[at]linaro[.]org.

Anyone can contribute to OP-TEE as long as it is understood that it will require
a sign-off. The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right to
pass it on as an open-source patch (see below). You thereby assure that you have
read and are following the rules stated in the `Developer Certificate of Origin`
as stated below.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

We have borrowed this procedure from the Linux kernel project to
improve tracking of who did what, and for legal reasons.

To sign-off a patch, just add a line saying:
```
    Signed-off-by: Random J Developer <random@developer.example.org>
```
using your real name (sorry, no pseudonyms or anonymous contributions.)

Refer also to [github.md](documentation/github.md) to setup a github accournt
in order to contribute to the project through issues reporting and pull
requests.

[BSD 2-Clause]: http://opensource.org/licenses/BSD-2-Clause
[BSD 3-Clause]: http://opensource.org/licenses/BSD-3-Clause
[GPLv2]: https://opensource.org/licenses/gpl-2.0
[build documentation]: documentation/build_system.md
[GlobalPlatform TEE specifications]: https://www.globalplatform.org/specificationsdevice.asp
[Linux kernel]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
[optee_client]: https://github.com/OP-TEE/optee_client
[optee_examples]: https://github.com/OP-TEE/optee_examples
[optee_os]: https://github.com/OP-TEE/optee_os
[optee_test]: https://github.com/OP-TEE/optee_test
