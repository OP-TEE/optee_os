OP-TEE
=======

This is the repository of OP-TEE (Open Portable Trusted Execution Environment),
the open-source TEE maintained by Linaro, with initial contributions from
STMicroelectronics, Ericsson and Linaro Limited.

What OP-TEE is
------

OP-TEE is designed primarily to rely on the ARM TrustZone(R) technology as the
underlying hardware isolation mechanism. However, it has been structured to be
compatible with any isolation technology suitable for the TEE concept and goals,
such as running as a virtual machine or on a dedicated CPU.

The main design goals for OP-TEE are:
-	Isolation - the TEE provides isolation from the Rich OS (typically,
	Linux/Android) and it protects the Trusted Applications (TAs) it
	executes from each other, using underlying HW support,
-	Small footprint - the TEE should remain small enough so that the TEE
	core, including all the code and data required to provide isolation, can
	reside in a reasonable amount of on-chip memory,
-	Portability - the TEE must be easily pluggable to different
	architectures and available HW, and it has to support various setups
	such as multiple TEEs or multiple client OSes.

Repository structure
------

OP-TEE is composed of three gits:
-	The optee-client git, containing the source code for the TEE client
	library in Linux. This component provides the TEE Client API as defined
	by the <a href="https://www.globalplatform.org/specificationsdevice.asp">GlobalPlatform
	TEE standard</a>. It is distributed under the BSD 2-clause open-source license.
-	The optee_os git, containing the source code for the TEE OS itself. This
	component provides the TEE Internal APIs as defined by the
	GlobalPlatform  TEE standard to the Trusted Applications that it
	executes. It is distributed mostly under the BSD 2-clause open-source
	license. It includes few external files under BSD 3-clause license or
	other free software licenses.
-	The optee_linuxdriver git, containing the source code for the TEE driver
	in Linux. This component implements a generic TEE driver, designed
	primarily for TEE implementations that rely on the ARM
	TrustZone(R)technology. It is distributed under the GPLv2 open-source
	license. Please note that re-distribution under other versions of the
	GPL license is not allowed. The rationale behind this limitation is to
	ensure that this code may be used on products which have security
	devices which prevent reloading the code. Such security devices would be
	incompatible with some licenses such as GPLv3 and so distribution under
	those licenses would be inconsistent with this goal. Therefore it is
	recommended that care be taken before redistributing any of the
	components under other license terms than those provided here.

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
