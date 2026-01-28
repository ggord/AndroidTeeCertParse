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
		return nil, fmt.Errorf("failed to parse certificate data: %v", err)
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

	// Navigate through TBSCertificate fields
	// Structure: [version] serialNumber signature issuer validity subject subjectPublicKeyInfo [extensions]
	currentOffset := elem.GetContentOffset()
	endOffset := elem.GetNextOffset()
	fieldIndex := 0

	for currentOffset < endOffset {
		field, err := ParseASN1Element(data, currentOffset)
		if err != nil {
			return nil, err
		}

		// Handle optional version field (CONTEXT[0])
		if fieldIndex == 0 && field.GetTagClass() == 2 && field.TagNumber == 0 {
			// Parse version
			versionOffset := field.GetContentOffset()
			versionElem, err := ParseASN1Element(data, versionOffset)
			if err == nil && versionElem.Tag == ASN1_INTEGER {
				tbs.Version = int(versionElem.GetIntegerValue())
			}
			currentOffset = field.GetNextOffset()
			fieldIndex++
			continue
		}

		// Serial Number (INTEGER)
		if fieldIndex == 0 || fieldIndex == 1 {
			if field.Tag == ASN1_INTEGER {
				tbs.SerialNumber = field.GetContent()
				currentOffset = field.GetNextOffset()
				fieldIndex = 2
				continue
			}
		}

		// Signature Algorithm (SEQUENCE) - skip for now
		if fieldIndex == 2 {
			if field.Tag == ASN1_SEQUENCE {
				currentOffset = field.GetNextOffset()
				fieldIndex = 3
				continue
			}
		}

		// Issuer (SEQUENCE)
		if fieldIndex == 3 {
			if field.Tag == ASN1_SEQUENCE {
				tbs.Issuer = parseName(data, field)
				currentOffset = field.GetNextOffset()
				fieldIndex = 4
				continue
			}
		}

		// Validity (SEQUENCE)
		if fieldIndex == 4 {
			if field.Tag == ASN1_SEQUENCE {
				tbs.Validity = parseValidity(data, field)
				currentOffset = field.GetNextOffset()
				fieldIndex = 5
				continue
			}
		}

		// Subject (SEQUENCE)
		if fieldIndex == 5 {
			if field.Tag == ASN1_SEQUENCE {
				tbs.Subject = parseName(data, field)
				currentOffset = field.GetNextOffset()
				fieldIndex = 6
				continue
			}
		}

		// SubjectPublicKeyInfo (SEQUENCE)
		if fieldIndex == 6 {
			if field.Tag == ASN1_SEQUENCE {
				tbs.PublicKey = parsePublicKeyInfo(data, field)
				currentOffset = field.GetNextOffset()
				fieldIndex = 7
				continue
			}
		}

		// Extensions (CONTEXT[3])
		if field.GetTagClass() == 2 && field.TagNumber == 3 {
			extensions, err := parseCertificateExtensions(data, field.GetContentOffset())
			if err != nil {
				log.Printf("Warning: failed to parse extensions: %v", err)
			} else {
				tbs.Extensions = extensions
			}
		}

		currentOffset = field.GetNextOffset()
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

	// Note: TEE extension may not be present in root/intermediate certificates
	// This is not an error

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
// Note: This parser relies on the fixed order of fields in the attestation record SEQUENCE.
// According to the Android Key Attestation specification, the fields appear in this order:
// 0: attestationVersion, 1: attestationSecurityLevel, 2: keymasterVersion,
// 3: keymasterSecurityLevel, 4: attestationChallenge, 5: uniqueId,
// 6: softwareEnforced, 7: teeEnforced
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

// parseName parses a Distinguished Name (DN) from a SEQUENCE
func parseName(data []byte, nameSeq *ASN1Element) Name {
	name := Name{}
	
	currentOffset := nameSeq.GetContentOffset()
	endOffset := nameSeq.GetNextOffset()

	for currentOffset < endOffset {
		// Each name component is a SET
		setElem, err := ParseASN1Element(data, currentOffset)
		if err != nil || setElem.Tag != ASN1_SET {
			currentOffset = setElem.GetNextOffset()
			continue
		}

		// Parse the SEQUENCE inside the SET
		seqOffset := setElem.GetContentOffset()
		seqElem, err := ParseASN1Element(data, seqOffset)
		if err != nil || seqElem.Tag != ASN1_SEQUENCE {
			currentOffset = setElem.GetNextOffset()
			continue
		}

		// Parse OID and value
		oidOffset := seqElem.GetContentOffset()
		oidElem, err := ParseASN1Element(data, oidOffset)
		if err != nil || oidElem.Tag != ASN1_OBJECT_IDENTIFIER {
			currentOffset = setElem.GetNextOffset()
			continue
		}

		// Get the value (usually a string)
		valueOffset := oidElem.GetNextOffset()
		valueElem, err := ParseASN1Element(data, valueOffset)
		if err != nil {
			currentOffset = setElem.GetNextOffset()
			continue
		}

		// Convert value to string
		var value string
		switch valueElem.Tag {
		case ASN1_PRINTABLE_STRING, ASN1_UTF8_STRING, ASN1_IA5_STRING:
			value = string(valueElem.GetContent())
		}

		// Map OID to field
		oid := oidElem.GetContent()
		switch {
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03:
			name.CommonName = value
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0a:
			name.Organization = value
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0b:
			name.OrganizationalUnit = value
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x06:
			name.Country = value
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x08:
			name.State = value
		case len(oid) == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x07:
			name.Locality = value
		}

		currentOffset = setElem.GetNextOffset()
	}

	return name
}

// parseValidity parses the Validity structure
func parseValidity(data []byte, validitySeq *ASN1Element) Validity {
	validity := Validity{}

	currentOffset := validitySeq.GetContentOffset()

	// Parse notBefore
	notBeforeElem, err := ParseASN1Element(data, currentOffset)
	if err == nil && (notBeforeElem.Tag == ASN1_UTCTIME || notBeforeElem.Tag == ASN1_GENERALIZEDTIME) {
		validity.NotBefore = string(notBeforeElem.GetContent())
		currentOffset = notBeforeElem.GetNextOffset()
	}

	// Parse notAfter
	notAfterElem, err := ParseASN1Element(data, currentOffset)
	if err == nil && (notAfterElem.Tag == ASN1_UTCTIME || notAfterElem.Tag == ASN1_GENERALIZEDTIME) {
		validity.NotAfter = string(notAfterElem.GetContent())
	}

	return validity
}

// parsePublicKeyInfo parses the SubjectPublicKeyInfo structure
func parsePublicKeyInfo(data []byte, pkiSeq *ASN1Element) PublicKeyInfo {
	pki := PublicKeyInfo{
		Algorithm: "Unknown",
		KeySize:   0,
	}

	currentOffset := pkiSeq.GetContentOffset()

	// Parse algorithm (SEQUENCE)
	algSeq, err := ParseASN1Element(data, currentOffset)
	if err != nil || algSeq.Tag != ASN1_SEQUENCE {
		return pki
	}

	// Parse algorithm OID
	oidOffset := algSeq.GetContentOffset()
	oidElem, err := ParseASN1Element(data, oidOffset)
	if err != nil || oidElem.Tag != ASN1_OBJECT_IDENTIFIER {
		return pki
	}

	// Identify common algorithms
	oid := oidElem.GetContent()
	if len(oid) == 7 && oid[0] == 0x2a && oid[1] == 0x86 && oid[2] == 0x48 && oid[3] == 0xce && oid[4] == 0x3d && oid[5] == 0x02 && oid[6] == 0x01 {
		pki.Algorithm = "EC"
		
		// Parse EC parameters to get curve info
		paramOffset := oidElem.GetNextOffset()
		if paramOffset < algSeq.GetNextOffset() {
			paramElem, err := ParseASN1Element(data, paramOffset)
			if err == nil && paramElem.Tag == ASN1_OBJECT_IDENTIFIER {
				curveOid := paramElem.GetContent()
				// Check for P-256 (1.2.840.10045.3.1.7)
				if len(curveOid) == 8 && curveOid[0] == 0x2a && curveOid[1] == 0x86 && curveOid[2] == 0x48 && curveOid[3] == 0xce && curveOid[4] == 0x3d && curveOid[5] == 0x03 && curveOid[6] == 0x01 && curveOid[7] == 0x07 {
					pki.Algorithm = "EC (P-256)"
					pki.KeySize = 256
				}
			}
		}
	} else if len(oid) == 9 && oid[0] == 0x2a && oid[1] == 0x86 && oid[2] == 0x48 && oid[3] == 0x86 && oid[4] == 0xf7 && oid[5] == 0x0d && oid[6] == 0x01 && oid[7] == 0x01 {
		// RSA encryption OIDs
		if oid[8] == 0x01 {
			pki.Algorithm = "RSA"
		}
		
		// Parse public key BIT STRING to get key size
		keyOffset := algSeq.GetNextOffset()
		keyElem, err := ParseASN1Element(data, keyOffset)
		if err == nil && keyElem.Tag == ASN1_BIT_STRING {
			// For RSA, the key size can be estimated from the bit string length
			// This is approximate but good enough for display
			pki.KeySize = int(keyElem.Length) * 8
		}
	}

	return pki
}
