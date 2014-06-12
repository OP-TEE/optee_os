OP-TEE
=======

This is the repository of OP-TEE (Open Portable Trusted Execution Environment), the open-source TEE maintained by STMicroelectronics, with initial contributions from STMicroelectronics, Ericsson, the Linaro industry association.

What OP-TEE is
------

OP-TEE is designed primarily to rely on the ARM TrustZone(R) technology as the underlying hardware isolation mechanism. However, it has been structured to be compatible with any isolation technology suitable for the TEE concept and goals, such as running as a virtual machine or on a dedicated CPU.

The main design goals for OP-TEE are:
-	Isolation - the TEE provides isolation from the Rich OS (typically, Linux/Android) and it protects the Trusted Applications (TAs) it executes from each other, using underlying HW support,
-	Small footprint - the TEE should remain small enough so that the TEE core, including all the code and data required to provide isolation, can reside in a reasonable amount of on-chip memory,
-	Portability - the TEE must be easily pluggable to different architectures and available HW, and it has to support various setups such as multiple TEEs or multiple client OSes.

Repository structure
------

OP-TEE is composed of three gits:
-	The optee-client git, containing the source code for the TEE client library in Linux. This component provides the TEE Client API as defined by the <a href="https://www.globalplatform.org/specificationsdevice.asp">GlobalPlatform TEE standard</a>. It is distributed under the BSD 2-clause open-source license.
-	The optee_os git, containing the source code for the TEE OS itself. This component provides the TEE Internal APIs as defined by the GlobalPlatform  TEE standard to the Trusted Applications that it executes. It is distributed mostly under the BSD 2-clause open-source license. It includes few external files under BSD 3-clause license or other free software licenses.
-	The optee_linuxdriver git, containing the source code for the TEE driver in Linux. This component implements a generic TEE driver, designed primarily for TEE implementations that rely on the ARM TrustZone(R)technology. It is distributed under the GPLv2 open-source license. Please note that re-distribution under other versions of the GPL license is not allowed. 	The rationale behind this limitation is to ensure that this code may be used on products which have security devices which prevent reloading the code. Such security devices would be incompatible with some licenses such as GPLv3 and so distribution under those licenses would be inconsistent with this goal. Therefore it is recommended that care be taken before redistributing any of the components under other license terms than those provided here.

Contributions
------

Contributions to OP-TEE are managed by the OP-TEE gatekeepers, whose contact email is op-tee-support[at]st[.]com.

Contributions must be original work of the contributor. In order to preserve the rights of the contributor while allowing distribution to and protection of the recipients of OP-TEE, the contributor must complete, sign and send the Contribution Agreement or a scanned copy to ST for counter-signature, prior to any contribution. The address where to send the agreement and other details will be provided upon contact with the OP-TEE gatekeepers.
Once the Contribution Agreement is complete, the contributor may propose contributions to the OP-TEE gatekeepers. Proposed Contributions are reviewed for acceptance by the OP-TEE gatekeepers and the OP-TEE community.

Submission of non-original work
------

You may submit work that is not your original creation separately from any Contribution, identifying the complete details of its source and of any license or other restriction of which you are personally aware. Such submissions are not subject to the Contribution Agreement. They are reviewed for acceptance by the OP-TEE gatekeepers and the OP-TEE community.
