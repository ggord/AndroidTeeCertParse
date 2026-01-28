package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

// NewTeeCertFromFile creates a new TeeCert from a file
func NewTeeCertFromFile(filename string) (*TeeCert, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}
	return NewTeeCert(data)
}

// NewTeeCert creates a new TeeCert from raw data
func NewTeeCert(data []byte) (*TeeCert, error) {
	cert := &TeeCert{
		Data: data,
	}

	// Parse X.509 certificate
	x509Cert, err := parseX509Certificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}
	cert.X509Cert = x509Cert

	return cert, nil
}

// parseX509Certificate parses the X.509 certificate structure
func parseX509Certificate(data []byte) (*X509Certificate, error) {
	// X.509 Certificate is a SEQUENCE
	elem, err := ParseASN1Element(data, 0)
	if err != nil {
		return nil, err
	}

	if elem.Tag != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected SEQUENCE for X.509 certificate, got 0x%02X", elem.Tag)
	}

	cert := &X509Certificate{}

	// Parse TBSCertificate (first element in the certificate SEQUENCE)
	tbsCert, err := parseTBSCertificate(data, elem.GetContentOffset())
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBSCertificate: %v", err)
	}
	cert.TBSCert = tbsCert

	return cert, nil
}

// parseTBSCertificate parses the TBSCertificate structure
func parseTBSCertificate(data []byte, offset int) (*TBSCertificate, error) {
	// TBSCertificate is a SEQUENCE
	elem, err := ParseASN1Element(data, offset)
	if err != nil {
		return nil, err
	}

	if elem.Tag != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected SEQUENCE for TBSCertificate, got 0x%02X", elem.Tag)
	}

	tbs := &TBSCertificate{}

	// Navigate through TBSCertificate fields to find Extensions
	// Structure: [version] serialNumber signature issuer validity subject subjectPublicKeyInfo [extensions]
	currentOffset := elem.GetContentOffset()
	endOffset := elem.GetNextOffset()

	for currentOffset < endOffset {
		field, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			return nil, err
		}

		// Check if this is the Extensions field (CONTEXT[3])
		if field.GetTagClass() == 2 && field.TagNumber == 3 {
			// Found Extensions
			extensions, err := parseCertificateExtensions(data, field.GetContentOffset())
			if err != nil {
				return nil, fmt.Errorf("failed to parse extensions: %v", err)
			}
			tbs.Extensions = extensions
			break
		}

		currentOffset = field.GetNextOffset()
	}

	if tbs.Extensions == nil {
		return nil, fmt.Errorf("extensions not found in TBSCertificate")
	}

	return tbs, nil
}

// parseCertificateExtensions parses the certificate extensions
func parseCertificateExtensions(data []byte, offset int) (*CertificateExtensions, error) {
	// Extensions is a SEQUENCE of Extension
	extSeq, err := ParseASN1Element(data, offset)
	if err != nil {
		return nil, err
	}

	if extSeq.Tag != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected SEQUENCE for Extensions, got 0x%02X", extSeq.Tag)
	}

	exts := &CertificateExtensions{}

	// Iterate through extensions to find TEE attestation extension
	currentOffset := extSeq.GetContentOffset()
	endOffset := extSeq.GetNextOffset()

	for currentOffset < endOffset {
		ext, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			return nil, err
		}

		if ext.Tag != ASN1_SEQUENCE {
			currentOffset = ext.GetNextOffset()
			continue
		}

		// Parse extension: SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
		extContentOffset := ext.GetContentOffset()

		// Parse OID
		oidElem, err := ParseASN1Element(data, extContentOffset)
		if err != nil {
			currentOffset = ext.GetNextOffset()
			continue
		}

		if oidElem.Tag == ASN1_OBJECT_IDENTIFIER {
			oidContent := oidElem.GetContent()
			// Check if this is the TEE attestation OID
			if bytes.Equal(oidContent, TEE_ATTESTATION_OID) {
				log.Println("[Native-TEE] Found TEE attestation extension")

				// Parse the extension value
				valueOffset := oidElem.GetNextOffset()

				// Check for optional critical BOOLEAN
				criticalElem, err := ParseASN1Element(data, valueOffset)
				if err == nil && criticalElem.Tag == ASN1_BOOLEAN {
					valueOffset = criticalElem.GetNextOffset()
				}

				// Parse extnValue OCTET STRING
				valueElem, err := ParseASN1Element(data, valueOffset)
				if err != nil {
					return nil, fmt.Errorf("failed to parse extension value: %v", err)
				}

				if valueElem.Tag != ASN1_OCTET_STRING {
					return nil, fmt.Errorf("expected OCTET STRING for extension value, got 0x%02X", valueElem.Tag)
				}

				// Parse TEE attestation extension
				teeExt, err := parseTEEAttestationExtension(data, valueElem.GetContentOffset())
				if err != nil {
					return nil, fmt.Errorf("failed to parse TEE attestation extension: %v", err)
				}
				exts.TEEExtension = teeExt
				break
			}
		}

		currentOffset = ext.GetNextOffset()
	}

	if exts.TEEExtension == nil {
		return nil, fmt.Errorf("TEE attestation extension not found")
	}

	return exts, nil
}

// parseTEEAttestationExtension parses the TEE attestation extension
func parseTEEAttestationExtension(data []byte, offset int) (*TEEAttestationExtension, error) {
	// The attestation record is a SEQUENCE
	recSeq, err := ParseASN1Element(data, offset)
	if err != nil {
		return nil, err
	}

	if recSeq.Tag != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected SEQUENCE for attestation record, got 0x%02X", recSeq.Tag)
	}

	attestationRecord, err := parseAttestationRecord(data, recSeq.GetContentOffset(), int(recSeq.Length))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation record: %v", err)
	}

	return &TEEAttestationExtension{
		AttestationRecord: attestationRecord,
	}, nil
}

// parseAttestationRecord parses the attestation record
func parseAttestationRecord(data []byte, offset int, length int) (*AttestationRecord, error) {
	record := &AttestationRecord{}

	endOffset := offset + length
	currentOffset := offset
	fieldIndex := 0

	for currentOffset < endOffset {
		field, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			return nil, err
		}

		switch fieldIndex {
		case 0: // Attestation Version
			if field.Tag == ASN1_INTEGER {
				record.AttestationVersion = uint32(field.GetIntegerValue())
			}
		case 1: // Attestation Security Level
			if field.Tag == ASN1_ENUMERATED {
				record.AttestationSecurityLevel = SecurityLevel(field.GetEnumeratedValue())
			}
		case 2: // Keymaster Version
			if field.Tag == ASN1_INTEGER {
				record.KeymasterVersion = uint32(field.GetIntegerValue())
			}
		case 3: // Keymaster Security Level
			if field.Tag == ASN1_ENUMERATED {
				record.KeymasterSecurityLevel = SecurityLevel(field.GetEnumeratedValue())
			}
		case 4: // Attestation Challenge
			if field.Tag == ASN1_OCTET_STRING {
				record.AttestationChallenge = field.GetContent()
			}
		case 5: // Unique ID
			if field.Tag == ASN1_OCTET_STRING {
				record.UniqueId = field.GetContent()
			}
		case 6: // Software Enforced
			if field.Tag == ASN1_SEQUENCE {
				authList, err := parseAuthorizationList(data, field.GetContentOffset(), int(field.Length), "Software Enforced")
				if err != nil {
					log.Printf("Warning: failed to parse Software Enforced: %v", err)
				} else {
					record.SoftwareEnforced = authList
				}
			}
		case 7: // TEE Enforced
			if field.Tag == ASN1_SEQUENCE {
				authList, err := parseAuthorizationList(data, field.GetContentOffset(), int(field.Length), "TEE Enforced")
				if err != nil {
					log.Printf("Warning: failed to parse TEE Enforced: %v", err)
				} else {
					record.TEEEnforced = authList
				}
			}
		}

		fieldIndex++
		currentOffset = field.GetNextOffset()
	}

	return record, nil
}

// parseAuthorizationList parses an authorization list
func parseAuthorizationList(data []byte, offset int, length int, name string) (*AuthorizationList, error) {
	log.Printf("[Native-TEE] ========== Parsing %s Authorization List ==========", name)
	log.Printf("[Native-TEE] Authorization list offset: %d, length: %d bytes", offset, length)

	authList := &AuthorizationList{}

	endOffset := offset + length
	currentOffset := offset

	for currentOffset < endOffset {
		tag, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			return nil, err
		}

		// Check if this is a Context tag
		if tag.GetTagClass() == 2 {
			tagNum := tag.TagNumber
			parseKeymasterTag(data, tag, tagNum, authList)
		}

		currentOffset = tag.GetNextOffset()
	}

	return authList, nil
}

// parseKeymasterTag parses a Keymaster tag
func parseKeymasterTag(data []byte, tag *ASN1Element, tagNum uint32, authList *AuthorizationList) {
	switch tagNum {
	case KM_TAG_ROOT_OF_TRUST:
		parseRootOfTrust(data, tag, authList)
	case KM_TAG_OS_VERSION:
		parseOSVersion(data, tag, authList)
	case KM_TAG_OS_PATCHLEVEL:
		parseOSPatchLevel(data, tag, authList)
	case KM_TAG_BOOT_PATCHLEVEL:
		parseBootPatchLevel(data, tag, authList)
	case KM_TAG_VENDOR_PATCHLEVEL:
		parseVendorPatchLevel(data, tag, authList)
	case KM_TAG_CREATION_DATETIME:
		parseCreationDateTime(data, tag, authList)
	case KM_TAG_ORIGIN:
		parseOrigin(data, tag, authList)
	// Add more tag parsers as needed
	}
}

// parseRootOfTrust parses the Root of Trust
func parseRootOfTrust(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()

	// Root of Trust is a SEQUENCE
	rotSeq, err := ParseASN1Element(data, offset)
	if err != nil || rotSeq.Tag != ASN1_SEQUENCE {
		return
	}

	rot := RootOfTrust{}
	currentOffset := rotSeq.GetContentOffset()
	endOffset := rotSeq.GetNextOffset()
	fieldIndex := 0

	for currentOffset < endOffset {
		field, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			break
		}

		switch fieldIndex {
		case 0: // Verified Boot Key
			if field.Tag == ASN1_OCTET_STRING {
				rot.VerifiedBootKey = field.GetContent()
			}
		case 1: // Device Locked
			if field.Tag == ASN1_BOOLEAN {
				rot.DeviceLocked = field.GetBooleanValue()
			}
		case 2: // Verified Boot State
			if field.Tag == ASN1_ENUMERATED {
				rot.VerifiedBootState = uint32(field.GetEnumeratedValue())
			}
		}

		fieldIndex++
		currentOffset = field.GetNextOffset()
	}

	authList.RootOfTrust = rot
}

// parseOSVersion parses the OS version
func parseOSVersion(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.OSVersion = uint32(intElem.GetIntegerValue())
	}
}

// parseOSPatchLevel parses the OS patch level
func parseOSPatchLevel(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.OSPatchLevel = uint32(intElem.GetIntegerValue())
	}
}

// parseBootPatchLevel parses the boot patch level
func parseBootPatchLevel(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.BootPatchLevel = uint32(intElem.GetIntegerValue())
	}
}

// parseVendorPatchLevel parses the vendor patch level
func parseVendorPatchLevel(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.VendorPatchLevel = uint32(intElem.GetIntegerValue())
	}
}

// parseCreationDateTime parses the creation datetime
func parseCreationDateTime(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.CreationDateTime = intElem.GetIntegerValue()
	}
}

// parseOrigin parses the origin
func parseOrigin(data []byte, tag *ASN1Element, authList *AuthorizationList) {
	offset := tag.GetContentOffset()
	intElem, err := ParseASN1Element(data, offset)
	if err == nil && intElem.Tag == ASN1_INTEGER {
		authList.Origin = uint32(intElem.GetIntegerValue())
	}
}
