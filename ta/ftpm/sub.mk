#
# The fTPM needs to overwrite some of the header files used in the
# reference implementation. The search order GCC uses is dependent on the
# order the '-I/include/path' arguments are passed in. This is depended on
# the optee_os build system which makes it brittle. Force including these
# files here will make sure the correct files are used first.
#

cppflags-y += -include ta/ftpm/reference/include/VendorString.h
cppflags-y += -include ta/ftpm/platform/include/Platform.h

cppflags-y += -DHASH_LIB=MBEDTLS -DSYM_LIB=TEE -DMATH_LIB=TEE
cppflags-y += -DALG_CAMELLIA=ALG_NO -DALG_KDF2=ALG_NO
cppflags-y += -DALG_SM3_256=NO -DALG_SM4=YES
cppflags-y += -D_ARM_ -DFAIL_TRACE=NO
cppflags-y += -DGCC -DSIMULATION=NO -DVTPM
cppflags-y += -DRSA_INSTRUMENT=NO
cppflags-y += -DCERTIFYX509_DEBUG=NO
ifeq ($(CFG_TA_DEBUG),y)
cppflags-y += -DCOMPILER_CHECKS=YES -DfTPMDebug -DRUNTIME_SIZE_CHECKS
cppflags-y += -DLIBRARY_COMPATIBILITY_CHECK
cppflags-y += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
else
cppflags-y += -DCOMPILER_CHECKS=NO -DRUNTIME_SIZE_CHECKS=NO
cppflags-y += -DLIBRARY_COMPATIBILITY_CHECK=NO
endif

global-incdirs-y += include
global-incdirs-y += reference/include
global-incdirs-y += platform/include

global-incdirs_ext-y += $(CFG_MS_TPM_20_REF)/TPMCmd/tpm/include
global-incdirs_ext-y += $(CFG_MS_TPM_20_REF)/TPMCmd/tpm/include/prototypes
global-incdirs_ext-y += $(CFG_MS_TPM_20_REF)/TPMCmd/Platform/include

cflags-y += -Wno-cast-align
cflags-y += -Wno-implicit-fallthrough
cflags-y += -Wno-cast-function-type
cflags-y += -Wno-suggest-attribute=noreturn
cflags-y += -Wno-switch-default
cflags-y += -Wno-redundant-decls
cflags-y += -Wno-strict-prototypes
cflags-y += -Wno-undef

cflags-platform/NVMem.c-y += -Wno-shadow
cflags-platform/NVMem.c-y += -Wno-incompatible-pointer-types
cflags-platform/NVMem.c-y += -Wno-declaration-after-statement
cflags-platform/NVMem.c-y += -Wno-old-style-definition
cflags-platform/NVMem.c-y += -Wno-nested-externs
cflags-platform/NVMem.c-y += -Wno-implicit-function-declaration
cflags-platform/NVMem.c-y += -Wno-missing-declarations
cflags-platform/NVMem.c-y += -Wno-missing-prototypes
cflags-platform/NvAdmin.c-y += -Wno-old-style-definition
cflags-platform/NvAdmin.c-y += -Wno-nested-externs
cflags-platform/NvAdmin.c-y += -Wno-implicit-function-declaration
cflags-platform/NvAdmin.c-y += -Wno-missing-prototypes
cflags-platform/Clock.c-y += -Wno-unused-variable
cflags-fTPM.c-y += -Wno-nested-externs
cflags-fTPM.c-y += -Wno-implicit-function-declaration
cflags-platform/EPS.c-y += -Wno-nested-externs
cflags-platform/EPS.c-y += -Wno-implicit-function-declaration
cflags-platform/AdminPPI.c-y += -Wno-missing-declarations
cflags-platform/AdminPPI.c-y += -Wno-missing-prototypes
cflags-platform/AdminPPI.c-y += -Wno-unknown-pragmas
cflags-platform/PlatformACT.c-y += -Wno-missing-declarations
cflags-platform/PlatformACT.c-y += -Wno-missing-prototypes
cflags-platform/fTPM_helpers.c-y += -Wno-missing-declarations
cflags-platform/fTPM_helpers.c-y += -Wno-missing-prototypes

srcs-y += platform/AdminPPI.c
srcs-y += platform/Cancel.c
srcs-y += platform/Clock.c
srcs-y += platform/Entropy.c
srcs-y += platform/LocalityPlat.c
srcs-y += platform/NvAdmin.c
srcs-y += platform/NVMem.c
srcs-y += platform/PowerPlat.c
srcs-y += platform/PlatformData.c
srcs-y += platform/PPPlat.c
srcs-y += platform/RunCommand.c
srcs-y += platform/Unique.c
srcs-y += platform/EPS.c
srcs-y += platform/PlatformACT.c
srcs-y += platform/fTPM_helpers.c

srcs-y += fTPM.c

ifeq ($(CFG_TA_MEASURED_BOOT),y)
# Support for Trusted Firmware Measured Boot.
srcs-y += platform/fTPM_event_log.c
srcs-y += platform/EventLogPrint.c
cppflags-y += -DEVENT_LOG_SIZE=$(CFG_TA_EVENT_LOG_SIZE)
cppflags-y += -DMEASURED_BOOT
endif


srcs-y += tee/TpmToTEEMath.c
srcs-y += tee/TpmToTEESupport.c
srcs-y += tee/TpmToTEESym.c

srcs_ext_base-y := $(CFG_MS_TPM_20_REF)/TPMCmd/tpm/src/
srcs_ext-y += X509/X509_ECC.c
srcs_ext-y += X509/X509_RSA.c
srcs_ext-y += X509/TpmASN1.c
srcs_ext-y += X509/X509_spt.c
srcs_ext-y += command/Attestation/CertifyX509.c
srcs_ext-y += command/Attestation/GetCommandAuditDigest.c
srcs_ext-y += command/Attestation/GetSessionAuditDigest.c
srcs_ext-y += command/Attestation/Attest_spt.c
srcs_ext-y += command/Attestation/Quote.c
srcs_ext-y += command/Attestation/Certify.c
srcs_ext-y += command/Attestation/CertifyCreation.c
srcs_ext-y += command/Attestation/GetTime.c
srcs_ext-y += command/Random/GetRandom.c
srcs_ext-y += command/Random/StirRandom.c
srcs_ext-y += command/NVStorage/NV_WriteLock.c
srcs_ext-y += command/NVStorage/NV_ReadPublic.c
srcs_ext-y += command/NVStorage/NV_spt.c
srcs_ext-y += command/NVStorage/NV_Increment.c
srcs_ext-y += command/NVStorage/NV_ChangeAuth.c
srcs_ext-y += command/NVStorage/NV_UndefineSpaceSpecial.c
srcs_ext-y += command/NVStorage/NV_SetBits.c
srcs_ext-y += command/NVStorage/NV_Write.c
srcs_ext-y += command/NVStorage/NV_GlobalWriteLock.c
srcs_ext-y += command/NVStorage/NV_Read.c
srcs_ext-y += command/NVStorage/NV_Extend.c
srcs_ext-y += command/NVStorage/NV_Certify.c
srcs_ext-y += command/NVStorage/NV_ReadLock.c
srcs_ext-y += command/NVStorage/NV_DefineSpace.c
srcs_ext-y += command/NVStorage/NV_UndefineSpace.c
srcs_ext-y += command/HashHMAC/HashSequenceStart.c
srcs_ext-y += command/HashHMAC/SequenceUpdate.c
srcs_ext-y += command/HashHMAC/MAC_Start.c
srcs_ext-y += command/HashHMAC/EventSequenceComplete.c
srcs_ext-y += command/HashHMAC/HMAC_Start.c
srcs_ext-y += command/HashHMAC/SequenceComplete.c
srcs_ext-y += command/Vendor/Vendor_TCG_Test.c
srcs_ext-y += command/Ecdaa/Commit.c
srcs_ext-y += command/Startup/Startup.c
srcs_ext-y += command/Startup/Shutdown.c
srcs_ext-y += command/FieldUpgrade/FieldUpgradeData.c
srcs_ext-y += command/FieldUpgrade/FirmwareRead.c
srcs_ext-y += command/FieldUpgrade/FieldUpgradeStart.c
srcs_ext-y += command/Capability/TestParms.c
srcs_ext-y += command/Capability/GetCapability.c
srcs_ext-y += command/ClockTimer/ACT_spt.c
srcs_ext-y += command/ClockTimer/ClockRateAdjust.c
srcs_ext-y += command/ClockTimer/ACT_SetTimeout.c
srcs_ext-y += command/ClockTimer/ClockSet.c
srcs_ext-y += command/ClockTimer/ReadClock.c
srcs_ext-y += command/Session/PolicyRestart.c
srcs_ext-y += command/Session/StartAuthSession.c
srcs_ext-y += command/EA/PolicyDuplicationSelect.c
srcs_ext-y += command/EA/PolicyPCR.c
srcs_ext-y += command/EA/PolicySecret.c
srcs_ext-y += command/EA/PolicyTicket.c
srcs_ext-y += command/EA/PolicyTemplate.c
srcs_ext-y += command/EA/PolicyNV.c
srcs_ext-y += command/EA/PolicyGetDigest.c
srcs_ext-y += command/EA/PolicyCpHash.c
srcs_ext-y += command/EA/PolicyOR.c
srcs_ext-y += command/EA/Policy_spt.c
srcs_ext-y += command/EA/PolicyLocality.c
srcs_ext-y += command/EA/PolicyAuthorize.c
srcs_ext-y += command/EA/PolicyAuthorizeNV.c
srcs_ext-y += command/EA/PolicyPassword.c
srcs_ext-y += command/EA/PolicyCounterTimer.c
srcs_ext-y += command/EA/PolicyAuthValue.c
srcs_ext-y += command/EA/PolicySigned.c
srcs_ext-y += command/EA/PolicyNameHash.c
srcs_ext-y += command/EA/PolicyNvWritten.c
srcs_ext-y += command/EA/PolicyPhysicalPresence.c
srcs_ext-y += command/EA/PolicyCommandCode.c
srcs_ext-y += command/Hierarchy/ChangePPS.c
srcs_ext-y += command/Hierarchy/HierarchyControl.c
srcs_ext-y += command/Hierarchy/HierarchyChangeAuth.c
srcs_ext-y += command/Hierarchy/ChangeEPS.c
srcs_ext-y += command/Hierarchy/ClearControl.c
srcs_ext-y += command/Hierarchy/Clear.c
srcs_ext-y += command/Hierarchy/SetPrimaryPolicy.c
srcs_ext-y += command/Hierarchy/CreatePrimary.c
srcs_ext-y += command/CommandAudit/SetCommandCodeAuditStatus.c
srcs_ext-y += command/Object/Object_spt.c
srcs_ext-y += command/Object/ReadPublic.c
srcs_ext-y += command/Object/Load.c
srcs_ext-y += command/Object/LoadExternal.c
srcs_ext-y += command/Object/MakeCredential.c
srcs_ext-y += command/Object/Unseal.c
srcs_ext-y += command/Object/CreateLoaded.c
srcs_ext-y += command/Object/ObjectChangeAuth.c
srcs_ext-y += command/Object/ActivateCredential.c
srcs_ext-y += command/Object/Create.c
srcs_ext-y += command/AttachedComponent/AC_GetCapability.c
srcs_ext-y += command/AttachedComponent/AC_spt.c
srcs_ext-y += command/AttachedComponent/AC_Send.c
srcs_ext-y += command/AttachedComponent/Policy_AC_SendSelect.c
srcs_ext-y += command/Signature/VerifySignature.c
srcs_ext-y += command/Signature/Sign.c
srcs_ext-y += command/Duplication/Import.c
srcs_ext-y += command/Duplication/Rewrap.c
srcs_ext-y += command/Duplication/Duplicate.c
srcs_ext-y += command/Symmetric/EncryptDecrypt2.c
srcs_ext-y += command/Symmetric/EncryptDecrypt_spt.c
srcs_ext-y += command/Symmetric/HMAC.c
srcs_ext-y += command/Symmetric/Hash.c
srcs_ext-y += command/Symmetric/EncryptDecrypt.c
srcs_ext-y += command/Symmetric/MAC.c
srcs_ext-y += command/Context/ContextSave.c
srcs_ext-y += command/Context/FlushContext.c
srcs_ext-y += command/Context/Context_spt.c
srcs_ext-y += command/Context/ContextLoad.c
srcs_ext-y += command/Context/EvictControl.c
srcs_ext-y += command/PCR/PCR_Reset.c
srcs_ext-y += command/PCR/PCR_Allocate.c
srcs_ext-y += command/PCR/PCR_Extend.c
srcs_ext-y += command/PCR/PCR_SetAuthValue.c
srcs_ext-y += command/PCR/PCR_Event.c
srcs_ext-y += command/PCR/PCR_SetAuthPolicy.c
srcs_ext-y += command/PCR/PCR_Read.c
srcs_ext-y += command/DA/DictionaryAttackParameters.c
srcs_ext-y += command/DA/DictionaryAttackLockReset.c
srcs_ext-y += command/Misc/PP_Commands.c
srcs_ext-y += command/Misc/SetAlgorithmSet.c
srcs_ext-y += command/Testing/GetTestResult.c
srcs_ext-y += command/Testing/SelfTest.c
srcs_ext-y += command/Testing/IncrementalSelfTest.c
srcs_ext-y += command/Asymmetric/ECC_Parameters.c
srcs_ext-y += command/Asymmetric/RSA_Encrypt.c
srcs_ext-y += command/Asymmetric/ECDH_ZGen.c
srcs_ext-y += command/Asymmetric/ECDH_KeyGen.c
srcs_ext-y += command/Asymmetric/ZGen_2Phase.c
srcs_ext-y += command/Asymmetric/ECC_Decrypt.c
srcs_ext-y += command/Asymmetric/RSA_Decrypt.c
srcs_ext-y += command/Asymmetric/EC_Ephemeral.c
srcs_ext-y += command/Asymmetric/ECC_Encrypt.c
srcs_ext-y += subsystem/DA.c
srcs_ext-y += subsystem/NvDynamic.c
srcs_ext-y += subsystem/Object.c
srcs_ext-y += subsystem/PP.c
srcs_ext-y += subsystem/Session.c
srcs_ext-y += subsystem/NvReserved.c
srcs_ext-y += subsystem/Hierarchy.c
srcs_ext-y += subsystem/Time.c
srcs_ext-y += subsystem/PCR.c
srcs_ext-y += subsystem/CommandAudit.c
srcs_ext-y += events/_TPM_Hash_Start.c
srcs_ext-y += events/_TPM_Init.c
srcs_ext-y += events/_TPM_Hash_Data.c
srcs_ext-y += events/_TPM_Hash_End.c
srcs_ext-y += crypt/CryptSmac.c
srcs_ext-y += crypt/CryptEccData.c
srcs_ext-y += crypt/CryptCmac.c
srcs_ext-y += crypt/BnMath.c
srcs_ext-y += crypt/CryptEccSignature.c
srcs_ext-y += crypt/AlgorithmTests.c
srcs_ext-y += crypt/CryptSelfTest.c
srcs_ext-y += crypt/Ticket.c
srcs_ext-y += crypt/CryptDes.c
srcs_ext-y += crypt/BnMemory.c
srcs_ext-y += crypt/CryptPrimeSieve.c
srcs_ext-y += crypt/CryptEccKeyExchange.c
srcs_ext-y += crypt/BnConvert.c
srcs_ext-y += crypt/CryptRand.c
srcs_ext-y += crypt/CryptEccMain.c
srcs_ext-y += crypt/CryptSym.c
srcs_ext-y += crypt/RsaKeyCache.c
srcs_ext-y += crypt/CryptUtil.c
srcs_ext-y += crypt/CryptEccCrypt.c
srcs_ext-y += crypt/CryptRsa.c
srcs_ext-y += crypt/CryptPrime.c
srcs_ext-y += crypt/PrimeData.c
srcs_ext-y += crypt/CryptHash.c
srcs_ext-y += support/Marshal.c
srcs_ext-y += support/MathOnByteBuffers.c
srcs_ext-y += support/TableDrivenMarshal.c
srcs_ext-y += support/PropertyCap.c
srcs_ext-y += support/Locality.c
srcs_ext-y += support/TableMarshalData.c
srcs_ext-y += support/Memory.c
srcs_ext-y += support/Response.c
srcs_ext-y += support/ResponseCodeProcessing.c
srcs_ext-y += support/Global.c
srcs_ext-y += support/Power.c
srcs_ext-y += support/AlgorithmCap.c
srcs_ext-y += support/CommandCodeAttributes.c
srcs_ext-y += support/Entity.c
srcs_ext-y += support/Handle.c
srcs_ext-y += support/TpmFail.c
srcs_ext-y += support/TpmSizeChecks.c
srcs_ext-y += support/Manufacture.c
srcs_ext-y += support/IoBuffers.c
srcs_ext-y += support/Bits.c
srcs_ext-y += main/SessionProcess.c
srcs_ext-y += main/CommandDispatcher.c
srcs_ext-y += main/ExecCommand.c
