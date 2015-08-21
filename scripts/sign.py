#!/usr/bin/env python
#
# Copyright (c) 2015, Linaro Limited
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import encoder as der_encoder

# Attribute ::= SEQUENCE {
#   attrType OBJECT IDENTIFIER,
#   attrValues SET OF AttributeValue }
#
# AttributeValue ::= ANY
class cms_attr_values(univ.SetOf): componentType = univ.Any()
class cms_attribute(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('attrType', univ.ObjectIdentifier()),
		namedtype.NamedType('attrValues', cms_attr_values())
	)

# SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
class cms_signed_attributes(univ.SetOf) : componentType = cms_attribute()

# FirmwarePackageIdentifier ::= SEQUENCE {
#   name PreferredOrLegacyPackageIdentifier,
#   stale PreferredOrLegacyStalePackageIdentifier OPTIONAL }
#
# PreferredOrLegacyPackageIdentifier ::= CHOICE {
#   preferred PreferredPackageIdentifier,
#   legacy OCTET STRING }
#
# PreferredPackageIdentifier ::= SEQUENCE {
#   fwPkgID OBJECT IDENTIFIER,
#   verNum INTEGER (0..MAX) }
#
# PreferredOrLegacyStalePackageIdentifier ::= CHOICE {
#   preferredStaleVerNum INTEGER (0..MAX),
#   legacyStaleVersion OCTET STRING }
class cms_preferred_or_legacy_stale_package_identifier(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('preferredStaleVerNum', univ.Integer()),
		namedtype.NamedType('legacyStaleVersion', univ.OctetString())
	)
class cms_preferred_package_identifier(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('fwPkgID', univ.ObjectIdentifier()),
		namedtype.NamedType('verNum', univ.Integer())
	)
class cms_preferred_or_legacy_package_identifier(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('preferred',
			cms_preferred_package_identifier()),
		namedtype.NamedType('legacy', univ.OctetString())
	)
class cms_firmware_package_identifer(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('name',
			cms_preferred_or_legacy_package_identifier()),
		namedtype.OptionalNamedType('stale',
			cms_preferred_or_legacy_stale_package_identifier())
	)

# TargetHardwareIdentifiers ::= SEQUENCE OF OBJECT IDENTIFIER
class cms_target_hardware_identifiers(univ.SequenceOf):
	componentType = univ.ObjectIdentifier()

# ContentInfo ::= SEQUENCE {
#   contentType          id-signedData, -- (1.2.840.113549.1.7.2)
#   content              SignedData
# }
#
# SignedData ::= SEQUENCE {
#   version              CMSVersion, -- always set to 3
#   digestAlgorithms     DigestAlgorithmIdentifiers, -- Only one
#   encapContentInfo     EncapsulatedContentInfo,
#   certificates [0] IMPLICIT CertificateSet OPTIONAL, -- Signer cert. path
#   crls [1] IMPLICIT    CertificateRevocationLists OPTIONAL , -- Optional
#   signerInfos          SignerInforms -- Only one
# }
#
# SignerInfos ::= SET OF SignerInfo -- Only one
#
# SignerInfo ::= SEQUENCE {
#   version              CMSVersion, -- always set to 3
#   sid                  SignerIdentifier,
#   digestAlgorithm      DigestAlgorithmIdentifier,
#   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL, -- Required
#   signatureAlgorithm   SignatureAlgorithmIdentifier,
#   signature            SignatureValue,
#   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL -- Optional
# }
#
# EncapsulatedContentInfo {
#   eContentType         id-encryptedData, -- (1.2.840.113549.1.7.6)
#                        -- OR --
#                        id-ct-compressedData,
#                                  -- (1.2.840.113549.1.9.16.1.9)
#                        -- OR --
#                        id-ct-firmwarePackage,
#                                  -- (1.2.840.113549.1.9.16.1.16)
#   eContent             OCTET STRING
# }                            -- Contains EncryptedData OR
#                              -- CompressedData OR
#                              -- FirmwarePkgData
#
# EncryptedData {
#   version              CMSVersion, -- Always set to 0
#   encryptedContentInfo EncryptedContentInfo,
#   unprotectedAttrs     UnprotectedAttributes -- Omit
# }
#
# EncryptedContentInfo {
#   contentType          id-ct-compressedData,
#                                  -- (1.2.840.113549.1.9.16.1.9)
#                        -- OR --
#                        id-ct-firmwarePackage,
#                                  -- (1.2.840.113549.1.9.16.1.16)
#   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
#   encryptedContent OCTET STRING
# }                                -- Contains CompressedData OR
#                                  -- FirmwarePkgData
#
# CompressedData {
#   version              CMSVersion, -- Always set to 0
#   compressionAlgorithm CompressionAlgorithmIdentifier,
#   encapContentInfo     EncapsulatedContentInfo
# }
#
# EncapsulatedContentInfo ::= SEQUENCE {
#   eContentType         id-ct-firmwarePackage,
#                                    -- (1.2.840.113549.1.9.16.1.16)
#   eContent             OCTET STRING -- Contains FirmwarePkgData
# }
#
# FirmwarePkgData         OCTET STRING -- Contains firmware package

class cms_encapsulated_content_info(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('eContentType', univ.ObjectIdentifier()),
		namedtype.NamedType('eContent', univ.OctetString())
	)

class cms_unprotected_attributes(univ.SetOf): componentType = cms_attribute()

class cms_encapsulated_content_info(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('eContentType', univ.ObjectIdentifier()),
		namedtype.NamedType('eContent', univ.OctetString())
	)

class cms_unsigned_attributes(univ.SetOf): componentType = cms_attribute()

class cms_signer_info(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('version', univ.Integer()),
		namedtype.NamedType('sid', univ.ObjectIdentifier()),
		namedtype.NamedType('digestAlgorithm', univ.ObjectIdentifier()),
		namedtype.OptionalNamedType('signedAttrs',
			cms_signed_attributes().subtype(
				implicitTag=tag.Tag(
					tag.tagClassContext,
					tag.tagFormatConstructed,
					0
				)
			)
		),
		namedtype.NamedType('signatureAlgorithm',
					univ.ObjectIdentifier()),
		namedtype.NamedType('signature', univ.OctetString()),
		namedtype.OptionalNamedType('unsignedAttrs',
			cms_unsigned_attributes().subtype(
				implicitTag=tag.Tag(
					tag.tagClassContext,
					tag.tagFormatConstructed,
					1
				)
			)
		)
	)

class cms_digest_algorithm_identifiers(univ.SetOf):
	componentType = univ.ObjectIdentifier()

class cms_signer_infos(univ.SetOf): componentType = cms_signer_info()

class cms_signed_data(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('version', univ.Integer()),
		namedtype.NamedType('digestAlgorithms',
				cms_digest_algorithm_identifiers()),
		namedtype.NamedType('encapContentInfo',
				cms_encapsulated_content_info()),
		namedtype.NamedType('signerInfos', cms_signer_infos())
	)

class cms_content_info(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('contentType', univ.ObjectIdentifier()),
		namedtype.NamedType('content', cms_signed_data())
	)

#   contentType          id-signedData, -- (1.2.840.113549.1.7.2)
cms_id_signed_data = univ.ObjectIdentifier('1.2.840.113549.1.7.2')


# id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
cms_id_content_type = univ.ObjectIdentifier('1.2.840.113549.1.9.3')

# id-aa-firmwarePackageID OBJECT IDENTIFIER ::= {
#  iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
#  smime(16) aa(2) 35 }
cms_id_aa_firmware_package_id = univ.ObjectIdentifier(
				'1.2.840.113549.1.9.16.2.35')

# id-ct-firmwarePackage OBJECT IDENTIFIER ::= {
#   iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
#   smime(16) ct(1) 16 }
cms_id_ct_firmware_package = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.16')

# id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#   us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
cms_id_message_digest = univ.ObjectIdentifier('1.2.840.113549.1.9.4')


# id-aa-targetHardwareIDs OBJECT IDENTIFIER ::= {
#   iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
#   smime(16) aa(2) 36 }
cms_id_aa_taget_hardware_ids = univ.ObjectIdentifier(
				'1.2.840.113549.1.9.16.2.36')


# Selected Algorithm OIDs
# SHA-256
cms_id_sha256 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')

# PKCS #1 version 1.5 signature algorithm with SHA-256
# pkcs-1  OBJECT IDENTIFIER  ::=  { iso(1) member-body(2)
#                              us(840) rsadsi(113549) pkcs(1) 1 }
# sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
cms_id_sha256_with_rsa_encryption = univ.ObjectIdentifier(
				'1.2.840.113549.1.1.11')

cms_id_dummy = univ.ObjectIdentifier('1.2.3.4.5')

def get_attr(attr_type, attr_value):
	attr_values = cms_attr_values()
	attr_values.setComponentByPosition(0, attr_value)

	attr = cms_attribute()
	attr.setComponentByName('attrType', attr_type)
	attr.setComponentByName('attrValues', attr_values)
	return attr

def get_firmware_package_identifier():
	oct_str = univ.OctetString(())

	pref_or_legacy_pid = cms_preferred_or_legacy_package_identifier()
	pref_or_legacy_pid.setComponentByName('legacy', oct_str)
	
	fwpid = cms_firmware_package_identifer();
	fwpid.setComponentByName('name', pref_or_legacy_pid);
	return fwpid;

def get_target_hardware_module_identifiers():
	hwid = cms_target_hardware_identifiers();
	hwid.setComponentByPosition(0, univ.ObjectIdentifier('1.2.3'))
	return hwid

def get_signed_attributes(digest):
	signed_attrs = cms_signed_attributes()

	signed_attrs.setComponentByPosition(0,
		get_attr(cms_id_content_type, cms_id_aa_firmware_package_id))

	signed_attrs.setComponentByPosition(1,
		get_attr(cms_id_message_digest, univ.OctetString(digest)))

	signed_attrs.setComponentByPosition(2,
		get_attr(cms_id_aa_firmware_package_id,
			get_firmware_package_identifier()))
	
	signed_attrs.setComponentByPosition(3,
		get_attr(cms_id_aa_taget_hardware_ids,
			get_target_hardware_module_identifiers()))

	return signed_attrs

def get_content_info(digest_oid, sign_oid, signed_attrs, fw_pkg_data, signature):
	# Copy signed_attrs into a subtype to fit in this SEQUENCE with regards
	# to tags
	local_sattrs = cms_signed_attributes().subtype(
		implicitTag=tag.Tag(
			tag.tagClassContext,
			tag.tagFormatConstructed,
			0
		)
	)
	for idx in range(len(signed_attrs)):
		local_sattrs.setComponentByPosition(idx,
			signed_attrs.getComponentByPosition(idx))
			

	digest_algorithms = cms_digest_algorithm_identifiers()
	digest_algorithms.setComponentByPosition(0, digest_oid)

	encap_content_info = cms_encapsulated_content_info()
	encap_content_info.setComponentByName('eContentType',
					cms_id_ct_firmware_package)
	encap_content_info.setComponentByName('eContent',
					univ.OctetString(fw_pkg_data))

	signer_info = cms_signer_info();
	signer_info.setComponentByName('version', univ.Integer(3))
	signer_info.setComponentByName('sid', cms_id_dummy)
	signer_info.setComponentByName('digestAlgorithm', digest_oid)
	signer_info.setComponentByName('signedAttrs', local_sattrs)
	signer_info.setComponentByName('signatureAlgorithm', sign_oid)
	signer_info.setComponentByName('signature', univ.OctetString(signature))
	signer_infos = cms_signer_infos()
	signer_infos.setComponentByPosition(0, signer_info)

	signed_data = cms_signed_data()
	signed_data.setComponentByName('version', univ.Integer(3))
	signed_data.setComponentByName('digestAlgorithms', digest_algorithms)
	signed_data.setComponentByName('encapContentInfo', encap_content_info)
	signed_data.setComponentByName('signerInfos', signer_infos)

	content_info = cms_content_info()
	content_info.setComponentByName('contentType', cms_id_signed_data)
	content_info.setComponentByName('content', signed_data)
	return content_info

def get_args():
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('--key', required=True, help='Name of key file')
	parser.add_argument('--in', required=True, dest='inf', \
			help='Name of in file')
	parser.add_argument('--out', required=True, help='Name of out file')
	return parser.parse_args()

def main():
	from Crypto.Signature import PKCS1_v1_5
	from Crypto.Hash import SHA256
	from Crypto.PublicKey import RSA
	import struct

	args = get_args()

	f = open(args.key, 'r')
	key = RSA.importKey(f.read())
	f.close()

	f = open(args.inf, 'r')
	img = f.read()
	f.close()

	signer = PKCS1_v1_5.new(key)
	sign_oid = cms_id_sha256_with_rsa_encryption;
	h = SHA256.new()
	digest_oid = cms_id_sha256

	digest_len = h.digest_size
	sig_len = len(signer.sign(h))
	img_size = len(img)

#	algo = 0x70004830	# TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
	h.update(img)

	signed_attrs = get_signed_attributes(h.digest())

	h.update(der_encoder.encode(signed_attrs))

	sig = signer.sign(h)

	content_info = get_content_info(digest_oid, sign_oid,
					signed_attrs, img, sig)

	f = open(args.out, 'w');
	f.write(der_encoder.encode(content_info))
	f.close()

if __name__ == "__main__":
	main()
