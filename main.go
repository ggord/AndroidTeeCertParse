package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// Parse command-line flags
	hexStr := flag.String("hex", "", "Hex string of certificate to parse")
	verbose := flag.Bool("verbose", false, "Enable verbose field-by-field parsing output")
	flag.Parse()

	// If hex string provided, parse it
	if *hexStr != "" {
		parseCertFromHex(*hexStr, *verbose)
		os.Exit(0)
	}

	// List of certificate paths to parse
	certPaths := []string{
		// Uncomment additional certificates to test
		// "assests/cert_k30pro.bin",
		"assests/cert_oneplus.bin",
		// "assests/cert_pixel4.bin",
		// "assests/cert_pixel6.bin",
		// Note: cert_xiaomi6x.bin has format issues in original data
		// "assests/cert_xiaomi6x.bin",
	}

	for _, certPath := range certPaths {
		parseCertFromFile(certPath, *verbose)
	}

	fmt.Printf("\n======================\n")
	os.Exit(0)
}

func parseCertFromHex(hexStr string, verbose bool) {
	fmt.Printf("\n======================\n")
	fmt.Printf("Parsing certificate from hex string\n")
	fmt.Printf("======================\n")

	// Decode hex string
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatalf("[Native-TEE] Error: Failed to decode hex string: %v", err)
	}

	// Parse certificate chain (may contain multiple certificates)
	parseCertificateChain(data, verbose)
}

func parseCertificateChain(data []byte, verbose bool) {
	offset := 0
	certIndex := 1

	for offset < len(data) {
		// Try to parse a certificate at this offset
		elem, err := ParseASN1Element(data, offset)
		if err != nil {
			log.Printf("[Native-TEE] Error: Failed to parse certificate at offset %d: %v", offset, err)
			break
		}

		if elem.Tag != ASN1_SEQUENCE {
			log.Printf("[Native-TEE] Warning: Expected SEQUENCE for certificate, got 0x%02X at offset %d", elem.Tag, offset)
			break
		}

		certData := data[offset:elem.GetNextOffset()]

		fmt.Printf("\n--- Certificate #%d (offset: %d, size: %d bytes) ---\n", certIndex, offset, len(certData))

		if verbose {
			// Print detailed ASN.1 structure with field names
			fmt.Printf("\n=== Detailed ASN.1 Field Dump ===\n")
			dumpASN1FieldsWithNames(certData, 0, 0, []string{"Certificate"})
			fmt.Printf("\n=== End of Detailed Dump ===\n\n")
		}

		cert, err := NewTeeCert(certData)
		if err != nil {
			log.Printf("[Native-TEE] Error: Failed to parse certificate #%d: %v", certIndex, err)
			offset = elem.GetNextOffset()
			certIndex++
			continue
		}

		printCertificateInfo(cert)

		// Move to next certificate
		offset = elem.GetNextOffset()
		certIndex++
	}
}

func parseCertFromFile(certPath string, verbose bool) {
	fmt.Printf("\n======================\n")
	fmt.Printf("Parsing certificate: %s\n", certPath)
	fmt.Printf("======================\n")

	// Read file data
	data, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("[Native-TEE] Error: Invalid certificate file or parsing failed: %v", err)
		return
	}

	if verbose {
		// Print detailed ASN.1 structure
		fmt.Printf("\n=== Detailed ASN.1 Field Dump ===\n")
		dumpASN1Fields(data, 0, 0)
		fmt.Printf("\n=== End of Detailed Dump ===\n\n")
	}

	cert, err := NewTeeCertFromFile(certPath)
	if err != nil {
		log.Printf("[Native-TEE] Error: Invalid certificate file or parsing failed: %v", err)
		return
	}

	printCertificateInfo(cert)
}

func printCertificateInfo(cert *TeeCert) {
	fmt.Println("[Native-TEE] Certificate parsed successfully!")

	// Print basic certificate information
	if cert.X509Cert != nil && cert.X509Cert.TBSCert != nil {
		tbs := cert.X509Cert.TBSCert
		
		// Print Subject
		fmt.Printf("\n--- Certificate Information ---\n")
		printDistinguishedName("Subject", tbs.Subject)
		printDistinguishedName("Issuer", tbs.Issuer)
		
		// Print Validity
		fmt.Printf("Validity:\n")
		fmt.Printf("  Not Before: %s\n", tbs.Validity.NotBefore)
		fmt.Printf("  Not After:  %s\n", tbs.Validity.NotAfter)
		
		// Print Serial Number
		if len(tbs.SerialNumber) > 0 {
			fmt.Printf("Serial Number: ")
			for i, b := range tbs.SerialNumber {
				if i > 0 {
					fmt.Printf(":")
				}
				fmt.Printf("%02X", b)
			}
			fmt.Println()
		}
		
		// Print Public Key Info
		if tbs.PublicKey.Algorithm != "" {
			fmt.Printf("Public Key: %s", tbs.PublicKey.Algorithm)
			if tbs.PublicKey.KeySize > 0 {
				fmt.Printf(" (%d bits)", tbs.PublicKey.KeySize)
			}
			fmt.Println()
		}
	}

	// Get attestation record with nil checks
	if cert.X509Cert == nil || cert.X509Cert.TBSCert == nil ||
		cert.X509Cert.TBSCert.Extensions == nil ||
		cert.X509Cert.TBSCert.Extensions.TEEExtension == nil ||
		cert.X509Cert.TBSCert.Extensions.TEEExtension.AttestationRecord == nil {
		fmt.Printf("\n--- TEE Attestation Extension ---\n")
		fmt.Println("Not present (standard X.509 certificate - likely root or intermediate CA)")
		return
	}

	attestationRecord := cert.X509Cert.TBSCert.Extensions.TEEExtension.AttestationRecord

	// Print TEE Attestation Information
	fmt.Printf("\n--- TEE Attestation Extension ---\n")
	fmt.Printf("Attestation Version: %d\n", attestationRecord.AttestationVersion)
	fmt.Printf("Attestation Security Level: %d", attestationRecord.AttestationSecurityLevel)
	switch attestationRecord.AttestationSecurityLevel {
	case SecurityLevelSoftware:
		fmt.Printf(" (Software)\n")
	case SecurityLevelTEE:
		fmt.Printf(" (TEE)\n")
	case SecurityLevelStrongBox:
		fmt.Printf(" (StrongBox)\n")
	default:
		fmt.Println()
	}
	
	fmt.Printf("Keymaster Version: %d\n", attestationRecord.KeymasterVersion)
	fmt.Printf("Keymaster Security Level: %d", attestationRecord.KeymasterSecurityLevel)
	switch attestationRecord.KeymasterSecurityLevel {
	case SecurityLevelSoftware:
		fmt.Printf(" (Software)\n")
	case SecurityLevelTEE:
		fmt.Printf(" (TEE)\n")
	case SecurityLevelStrongBox:
		fmt.Printf(" (StrongBox)\n")
	default:
		fmt.Println()
	}

	// Get Root of Trust (could be in Software Enforced or TEE Enforced)
	var rootOfTrust *RootOfTrust
	if attestationRecord.SoftwareEnforced != nil && len(attestationRecord.SoftwareEnforced.RootOfTrust.VerifiedBootKey) > 0 {
		rootOfTrust = &attestationRecord.SoftwareEnforced.RootOfTrust
	} else if attestationRecord.TEEEnforced != nil && len(attestationRecord.TEEEnforced.RootOfTrust.VerifiedBootKey) > 0 {
		rootOfTrust = &attestationRecord.TEEEnforced.RootOfTrust
	} else if attestationRecord.SoftwareEnforced != nil {
		rootOfTrust = &attestationRecord.SoftwareEnforced.RootOfTrust
	} else if attestationRecord.TEEEnforced != nil {
		rootOfTrust = &attestationRecord.TEEEnforced.RootOfTrust
	}

	if rootOfTrust != nil {
		fmt.Printf("\n--- Root of Trust ---\n")
		fmt.Printf("Device Locked: %v\n", rootOfTrust.DeviceLocked)
		fmt.Printf("Verified Boot State: %d", rootOfTrust.VerifiedBootState)
		switch rootOfTrust.VerifiedBootState {
		case 0:
			fmt.Printf(" (Verified)\n")
		case 1:
			fmt.Printf(" (Self-Signed)\n")
		case 2:
			fmt.Printf(" (Unverified)\n")
		case 3:
			fmt.Printf(" (Failed)\n")
		default:
			fmt.Println()
		}
		fmt.Printf("Verified Boot Key Size: %d bytes\n", len(rootOfTrust.VerifiedBootKey))
		if len(rootOfTrust.VerifiedBootKey) >= 8 {
			fmt.Printf("Verified Boot Key (first 8 bytes): %02X %02X %02X %02X %02X %02X %02X %02X\n",
				rootOfTrust.VerifiedBootKey[0], rootOfTrust.VerifiedBootKey[1],
				rootOfTrust.VerifiedBootKey[2], rootOfTrust.VerifiedBootKey[3],
				rootOfTrust.VerifiedBootKey[4], rootOfTrust.VerifiedBootKey[5],
				rootOfTrust.VerifiedBootKey[6], rootOfTrust.VerifiedBootKey[7])
		}
	}

	// Print OS Version and Patch Levels
	if attestationRecord.SoftwareEnforced != nil {
		if attestationRecord.SoftwareEnforced.OSVersion > 0 || 
		   attestationRecord.SoftwareEnforced.OSPatchLevel > 0 || 
		   attestationRecord.SoftwareEnforced.BootPatchLevel > 0 {
			fmt.Printf("\n--- Software Enforced ---\n")
			if attestationRecord.SoftwareEnforced.OSVersion > 0 {
				fmt.Printf("OS Version: %d\n", attestationRecord.SoftwareEnforced.OSVersion)
			}
			if attestationRecord.SoftwareEnforced.OSPatchLevel > 0 {
				fmt.Printf("OS Patch Level: %d\n", attestationRecord.SoftwareEnforced.OSPatchLevel)
			}
			if attestationRecord.SoftwareEnforced.BootPatchLevel > 0 {
				fmt.Printf("Boot Patch Level: %d\n", attestationRecord.SoftwareEnforced.BootPatchLevel)
			}
		}
	}
	if attestationRecord.TEEEnforced != nil {
		if attestationRecord.TEEEnforced.OSVersion > 0 || 
		   attestationRecord.TEEEnforced.OSPatchLevel > 0 || 
		   attestationRecord.TEEEnforced.BootPatchLevel > 0 {
			fmt.Printf("\n--- TEE Enforced ---\n")
			if attestationRecord.TEEEnforced.OSVersion > 0 {
				fmt.Printf("OS Version: %d\n", attestationRecord.TEEEnforced.OSVersion)
			}
			if attestationRecord.TEEEnforced.OSPatchLevel > 0 {
				fmt.Printf("OS Patch Level: %d\n", attestationRecord.TEEEnforced.OSPatchLevel)
			}
			if attestationRecord.TEEEnforced.BootPatchLevel > 0 {
				fmt.Printf("Boot Patch Level: %d\n", attestationRecord.TEEEnforced.BootPatchLevel)
			}
		}
	}
}

// printDistinguishedName prints a Distinguished Name
func printDistinguishedName(label string, name Name) {
	fmt.Printf("%s:\n", label)
	if name.CommonName != "" {
		fmt.Printf("  CN (Common Name): %s\n", name.CommonName)
	}
	if name.Organization != "" {
		fmt.Printf("  O (Organization): %s\n", name.Organization)
	}
	if name.OrganizationalUnit != "" {
		fmt.Printf("  OU (Organizational Unit): %s\n", name.OrganizationalUnit)
	}
	if name.Country != "" {
		fmt.Printf("  C (Country): %s\n", name.Country)
	}
	if name.State != "" {
		fmt.Printf("  ST (State): %s\n", name.State)
	}
	if name.Locality != "" {
		fmt.Printf("  L (Locality): %s\n", name.Locality)
	}
}

// dumpASN1Fields recursively dumps all ASN.1 fields with detailed information
func dumpASN1Fields(data []byte, offset int, depth int) int {
	if offset >= len(data) {
		return offset
	}

	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	elem, err := ParseASN1Element(data, offset)
	if err != nil {
		fmt.Printf("%s[ERROR at offset %d: %v]\n", indent, offset, err)
		return len(data)
	}

	// Print field information
	tagClass := elem.GetTagClass()
	tagClassStr := ""
	switch tagClass {
	case 0:
		tagClassStr = "Universal"
	case 1:
		tagClassStr = "Application"
	case 2:
		tagClassStr = "Context"
	case 3:
		tagClassStr = "Private"
	}

	constructed := ""
	if elem.IsConstructed() {
		constructed = " CONSTRUCTED"
	} else {
		constructed = " PRIMITIVE"
	}

	// Get tag type description
	tagType := getTagTypeName(elem.Tag, tagClass)

	fmt.Printf("%sOffset %04d: [%s%s] Tag=0x%02X (%s) Length=%d TagNumber=%d\n",
		indent, offset, tagClassStr, constructed, elem.Tag, tagType, elem.Length, elem.TagNumber)

	// Print content hex dump for primitive types
	content := elem.GetContent()
	if !elem.IsConstructed() && len(content) > 0 && len(content) <= 64 {
		fmt.Printf("%s  Content (hex): ", indent)
		for i, b := range content {
			if i > 0 && i%16 == 0 {
				fmt.Printf("\n%s                 ", indent)
			}
			fmt.Printf("%02X ", b)
		}
		fmt.Println()

		// For printable strings, also show the text
		if elem.Tag == ASN1_PRINTABLE_STRING || elem.Tag == ASN1_UTF8_STRING || elem.Tag == ASN1_IA5_STRING {
			fmt.Printf("%s  Content (text): %s\n", indent, string(content))
		} else if elem.Tag == ASN1_INTEGER && len(content) <= 8 {
			fmt.Printf("%s  Content (int):  %d\n", indent, elem.GetIntegerValue())
		} else if elem.Tag == ASN1_BOOLEAN {
			fmt.Printf("%s  Content (bool): %v\n", indent, elem.GetBooleanValue())
		} else if elem.Tag == ASN1_ENUMERATED {
			fmt.Printf("%s  Content (enum): %d\n", indent, elem.GetEnumeratedValue())
		}
	} else if len(content) > 64 {
		fmt.Printf("%s  Content: %d bytes (too large to display)\n", indent, len(content))
		
		// Try to parse OCTET STRING content as nested ASN.1
		if elem.Tag == ASN1_OCTET_STRING && len(content) > 0 {
			// Check if the first byte looks like a valid ASN.1 tag
			if content[0] == ASN1_SEQUENCE || content[0] == ASN1_SET || 
			   (content[0] & 0x1F) > 0 {
				fmt.Printf("%s  > Parsing nested ASN.1 content:\n", indent)
				nestedOffset := 0
				for nestedOffset < len(content) {
					nestedOffset = dumpASN1Fields(content, nestedOffset, depth+1)
					if nestedOffset >= len(content) {
						break
					}
				}
			}
		}
	}

	// Recursively parse constructed types
	if elem.IsConstructed() {
		currentOffset := elem.GetContentOffset()
		endOffset := elem.GetNextOffset()
		for currentOffset < endOffset {
			currentOffset = dumpASN1Fields(data, currentOffset, depth+1)
			if currentOffset >= endOffset {
				break
			}
		}
	}

	return elem.GetNextOffset()
}

// dumpASN1FieldsWithNames recursively dumps all ASN.1 fields with certificate field names
func dumpASN1FieldsWithNames(data []byte, offset int, depth int, path []string) int {
	if offset >= len(data) {
		return offset
	}

	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	elem, err := ParseASN1Element(data, offset)
	if err != nil {
		fmt.Printf("%s[ERROR at offset %d: %v]\n", indent, offset, err)
		return len(data)
	}

	// Get field name based on path
	fieldName := getFieldName(path, elem, offset, data)

	// Print field information
	tagClass := elem.GetTagClass()
	tagClassStr := ""
	switch tagClass {
	case 0:
		tagClassStr = "Universal"
	case 1:
		tagClassStr = "Application"
	case 2:
		tagClassStr = "Context"
	case 3:
		tagClassStr = "Private"
	}

	constructed := ""
	if elem.IsConstructed() {
		constructed = " CONSTRUCTED"
	} else {
		constructed = " PRIMITIVE"
	}

	// Get tag type description
	tagType := getTagTypeName(elem.Tag, tagClass)

	// Print with field name
	if fieldName != "" {
		fmt.Printf("%sOffset %04d: [%s%s] Tag=0x%02X (%s) Length=%d TagNumber=%d - Field: %s\n",
			indent, offset, tagClassStr, constructed, elem.Tag, tagType, elem.Length, elem.TagNumber, fieldName)
	} else {
		fmt.Printf("%sOffset %04d: [%s%s] Tag=0x%02X (%s) Length=%d TagNumber=%d\n",
			indent, offset, tagClassStr, constructed, elem.Tag, tagType, elem.Length, elem.TagNumber)
	}

	// Print content hex dump for primitive types
	content := elem.GetContent()
	if !elem.IsConstructed() && len(content) > 0 && len(content) <= 64 {
		fmt.Printf("%s  Content (hex): ", indent)
		for i, b := range content {
			if i > 0 && i%16 == 0 {
				fmt.Printf("\n%s                 ", indent)
			}
			fmt.Printf("%02X ", b)
		}
		fmt.Println()

		// For printable strings, also show the text
		if elem.Tag == ASN1_PRINTABLE_STRING || elem.Tag == ASN1_UTF8_STRING || elem.Tag == ASN1_IA5_STRING {
			fmt.Printf("%s  Content (text): %s\n", indent, string(content))
		} else if elem.Tag == ASN1_INTEGER && len(content) <= 8 {
			fmt.Printf("%s  Content (int):  %d\n", indent, elem.GetIntegerValue())
		} else if elem.Tag == ASN1_BOOLEAN {
			fmt.Printf("%s  Content (bool): %v\n", indent, elem.GetBooleanValue())
		} else if elem.Tag == ASN1_ENUMERATED {
			fmt.Printf("%s  Content (enum): %d\n", indent, elem.GetEnumeratedValue())
		}
	} else if len(content) > 64 {
		fmt.Printf("%s  Content: %d bytes (too large to display)\n", indent, len(content))
		
		// Try to parse OCTET STRING content as nested ASN.1
		if elem.Tag == ASN1_OCTET_STRING && len(content) > 0 {
			// Check if the first byte looks like a valid ASN.1 tag
			if content[0] == ASN1_SEQUENCE || content[0] == ASN1_SET || 
			   (content[0] & 0x1F) > 0 {
				fmt.Printf("%s  > Parsing nested ASN.1 content:\n", indent)
				nestedOffset := 0
				nestedPath := append(path, fieldName)
				for nestedOffset < len(content) {
					nestedOffset = dumpASN1FieldsWithNames(content, nestedOffset, depth+1, nestedPath)
					if nestedOffset >= len(content) {
						break
					}
				}
			}
		}
	}

	// Recursively parse constructed types
	if elem.IsConstructed() {
		currentOffset := elem.GetContentOffset()
		endOffset := elem.GetNextOffset()
		childIndex := 0
		for currentOffset < endOffset {
			newPath := append(path, fieldName)
			if fieldName == "" {
				newPath = path
			}
			// Add child index for tracking
			newPath = append(newPath, fmt.Sprintf("[%d]", childIndex))
			currentOffset = dumpASN1FieldsWithNames(data, currentOffset, depth+1, newPath)
			if currentOffset >= endOffset {
				break
			}
			childIndex++
		}
	}

	return elem.GetNextOffset()
}

// getFieldName returns the certificate field name based on the path and context
func getFieldName(path []string, elem *ASN1Element, offset int, data []byte) string {
	if len(path) == 0 {
		return ""
	}

	// Get the current level in the certificate structure
	currentPath := path[len(path)-1]

	// Certificate root structure
	if currentPath == "Certificate" && elem.Tag == ASN1_SEQUENCE {
		return "Certificate"
	}

	// Inside Certificate
	if len(path) >= 2 && path[len(path)-2] == "Certificate" {
		if currentPath == "[0]" && elem.Tag == ASN1_SEQUENCE {
			return "TBSCertificate"
		}
		if currentPath == "[1]" && elem.Tag == ASN1_SEQUENCE {
			return "SignatureAlgorithm"
		}
		if currentPath == "[2]" && elem.Tag == ASN1_BIT_STRING {
			return "SignatureValue"
		}
	}

	// Inside TBSCertificate
	if len(path) >= 3 && path[len(path)-3] == "Certificate" && path[len(path)-2] == "[0]" {
		tagClass := elem.GetTagClass()
		if currentPath == "[0]" && tagClass == 2 && elem.TagNumber == 0 {
			return "Version"
		}
		// Check if version is present by looking at the tag
		versionPresent := false
		if len(path) >= 4 && path[len(path)-4] == "Certificate" {
			// Try to detect version by checking offset
			firstElem, _ := ParseASN1Element(data, offset-offset) // This is a simplified check
			if firstElem != nil && firstElem.GetTagClass() == 2 {
				versionPresent = true
			}
		}
		
		baseIndex := 0
		if versionPresent {
			baseIndex = 1
		}
		
		idx := parseChildIndex(currentPath)
		if idx == baseIndex && elem.Tag == ASN1_INTEGER {
			return "SerialNumber"
		}
		if idx == baseIndex+1 && elem.Tag == ASN1_SEQUENCE {
			return "Signature"
		}
		if idx == baseIndex+2 && elem.Tag == ASN1_SEQUENCE {
			return "Issuer"
		}
		if idx == baseIndex+3 && elem.Tag == ASN1_SEQUENCE {
			return "Validity"
		}
		if idx == baseIndex+4 && elem.Tag == ASN1_SEQUENCE {
			return "Subject"
		}
		if idx == baseIndex+5 && elem.Tag == ASN1_SEQUENCE {
			return "SubjectPublicKeyInfo"
		}
		if tagClass == 2 && elem.TagNumber == 3 {
			return "Extensions"
		}
	}

	// Inside Validity
	if len(path) >= 2 && (path[len(path)-2] == "Validity" || 
	   (len(path) >= 3 && path[len(path)-3] == "Validity")) {
		if currentPath == "[0]" && (elem.Tag == ASN1_UTCTIME || elem.Tag == ASN1_GENERALIZEDTIME) {
			return "NotBefore"
		}
		if currentPath == "[1]" && (elem.Tag == ASN1_UTCTIME || elem.Tag == ASN1_GENERALIZEDTIME) {
			return "NotAfter"
		}
	}

	// Inside Issuer or Subject (Name)
	if len(path) >= 2 && (path[len(path)-2] == "Issuer" || path[len(path)-2] == "Subject") {
		if elem.Tag == ASN1_SET {
			return "RDN (Relative Distinguished Name)"
		}
	}

	// Inside RDN - AttributeTypeAndValue
	if len(path) >= 3 && strings.Contains(path[len(path)-2], "RDN") {
		if elem.Tag == ASN1_SEQUENCE {
			return "AttributeTypeAndValue"
		}
	}

	// Inside AttributeTypeAndValue
	if len(path) >= 2 && strings.Contains(path[len(path)-2], "AttributeTypeAndValue") {
		if currentPath == "[0]" && elem.Tag == ASN1_OBJECT_IDENTIFIER {
			return "AttributeType (OID)"
		}
		if currentPath == "[1]" {
			// Read OID to determine attribute name
			if offset >= 2 {
				return "AttributeValue"
			}
		}
	}

	// SubjectPublicKeyInfo
	if len(path) >= 2 && path[len(path)-2] == "SubjectPublicKeyInfo" {
		if currentPath == "[0]" && elem.Tag == ASN1_SEQUENCE {
			return "Algorithm"
		}
		if currentPath == "[1]" && elem.Tag == ASN1_BIT_STRING {
			return "SubjectPublicKey"
		}
	}

	// Extensions
	if len(path) >= 2 && path[len(path)-2] == "Extensions" {
		if elem.Tag == ASN1_SEQUENCE {
			return "Extensions (SEQUENCE)"
		}
	}

	if len(path) >= 3 && strings.Contains(path[len(path)-3], "Extensions") {
		if elem.Tag == ASN1_SEQUENCE {
			return "Extension"
		}
	}

	// Inside Extension
	if len(path) >= 2 && path[len(path)-2] == "Extension" {
		if currentPath == "[0]" && elem.Tag == ASN1_OBJECT_IDENTIFIER {
			return "ExtensionID (OID)"
		}
		if currentPath == "[1]" && elem.Tag == ASN1_BOOLEAN {
			return "Critical"
		}
		if elem.Tag == ASN1_OCTET_STRING {
			return "ExtensionValue"
		}
	}

	// TEE Attestation Extension (nested in OCTET STRING)
	// When we're at offset 0 of a nested parse and it's a SEQUENCE, and the parent was ExtensionValue
	if offset == 0 && elem.Tag == ASN1_SEQUENCE {
		for i := len(path) - 1; i >= 0; i-- {
			if strings.Contains(path[i], "ExtensionValue") {
				return "KeyDescription (Attestation Record)"
			}
		}
	}

	// Inside KeyDescription
	if len(path) >= 2 && strings.Contains(path[len(path)-2], "KeyDescription") {
		idx := parseChildIndex(currentPath)
		if idx == 0 && elem.Tag == ASN1_INTEGER {
			return "AttestationVersion"
		}
		if idx == 1 && elem.Tag == ASN1_ENUMERATED {
			return "AttestationSecurityLevel"
		}
		if idx == 2 && elem.Tag == ASN1_INTEGER {
			return "KeymasterVersion"
		}
		if idx == 3 && elem.Tag == ASN1_ENUMERATED {
			return "KeymasterSecurityLevel"
		}
		if idx == 4 && elem.Tag == ASN1_OCTET_STRING {
			return "AttestationChallenge"
		}
		if idx == 5 && elem.Tag == ASN1_OCTET_STRING {
			return "UniqueId"
		}
		if idx == 6 && elem.Tag == ASN1_SEQUENCE {
			return "SoftwareEnforced (AuthorizationList)"
		}
		if idx == 7 && elem.Tag == ASN1_SEQUENCE {
			return "TeeEnforced (AuthorizationList)"
		}
	}

	// Inside AuthorizationList - check if we're in the path that leads to AuthorizationList
	for i := len(path) - 1; i >= 0; i-- {
		if strings.Contains(path[i], "SoftwareEnforced") || strings.Contains(path[i], "TeeEnforced") || strings.Contains(path[i], "AuthorizationList") {
			tagClass := elem.GetTagClass()
			if tagClass == 2 { // Context tags
				return getKeymasterTagName(int(elem.TagNumber))
			}
			break
		}
	}

	return ""
}

// parseChildIndex extracts the numeric index from a path component like "[0]"
func parseChildIndex(s string) int {
	if len(s) >= 3 && s[0] == '[' && s[len(s)-1] == ']' {
		var idx int
		fmt.Sscanf(s, "[%d]", &idx)
		return idx
	}
	return -1
}

// getKeymasterTagName returns the Keymaster tag name for a given tag number
func getKeymasterTagName(tagNumber int) string {
	// Keymaster tag numbers (from Android documentation)
	switch tagNumber {
	case 1:
		return "KM_TAG_PURPOSE"
	case 2:
		return "KM_TAG_ALGORITHM"
	case 3:
		return "KM_TAG_KEY_SIZE"
	case 4:
		return "KM_TAG_BLOCK_MODE"
	case 5:
		return "KM_TAG_DIGEST"
	case 6:
		return "KM_TAG_PADDING"
	case 10:
		return "KM_TAG_EC_CURVE"
	case 200:
		return "KM_TAG_RSA_PUBLIC_EXPONENT"
	case 303:
		return "KM_TAG_ROLLBACK_RESISTANCE"
	case 503:
		return "KM_TAG_BOOTLOADER_ONLY"
	case 504:
		return "KM_TAG_ACTIVE_DATETIME"
	case 505:
		return "KM_TAG_ORIGINATION_EXPIRE_DATETIME"
	case 506:
		return "KM_TAG_USAGE_EXPIRE_DATETIME"
	case 701:
		return "KM_TAG_CREATION_DATETIME"
	case 702:
		return "KM_TAG_ORIGIN"
	case 704:
		return "KM_TAG_ROOT_OF_TRUST"
	case 705:
		return "KM_TAG_OS_VERSION"
	case 706:
		return "KM_TAG_OS_PATCHLEVEL"
	case 709:
		return "KM_TAG_ATTESTATION_APPLICATION_ID"
	case 710:
		return "KM_TAG_ATTESTATION_ID_BRAND"
	case 711:
		return "KM_TAG_ATTESTATION_ID_DEVICE"
	case 712:
		return "KM_TAG_ATTESTATION_ID_PRODUCT"
	case 713:
		return "KM_TAG_ATTESTATION_ID_SERIAL"
	case 714:
		return "KM_TAG_ATTESTATION_ID_IMEI"
	case 715:
		return "KM_TAG_ATTESTATION_ID_MEID"
	case 716:
		return "KM_TAG_ATTESTATION_ID_MANUFACTURER"
	case 717:
		return "KM_TAG_ATTESTATION_ID_MODEL"
	case 718:
		return "KM_TAG_VENDOR_PATCHLEVEL"
	case 719:
		return "KM_TAG_BOOT_PATCHLEVEL"
	default:
		return fmt.Sprintf("KM_TAG_%d", tagNumber)
	}
}

// getTagTypeName returns a human-readable name for an ASN.1 tag
func getTagTypeName(tag byte, tagClass byte) string {
	if tagClass == 0 { // Universal
		switch tag {
		case ASN1_BOOLEAN:
			return "BOOLEAN"
		case ASN1_INTEGER:
			return "INTEGER"
		case ASN1_BIT_STRING:
			return "BIT STRING"
		case ASN1_OCTET_STRING:
			return "OCTET STRING"
		case ASN1_NULL:
			return "NULL"
		case ASN1_OBJECT_IDENTIFIER:
			return "OBJECT IDENTIFIER"
		case ASN1_ENUMERATED:
			return "ENUMERATED"
		case ASN1_UTF8_STRING:
			return "UTF8String"
		case ASN1_PRINTABLE_STRING:
			return "PrintableString"
		case ASN1_IA5_STRING:
			return "IA5String"
		case ASN1_UTCTIME:
			return "UTCTime"
		case ASN1_GENERALIZEDTIME:
			return "GeneralizedTime"
		case ASN1_SEQUENCE:
			return "SEQUENCE"
		case ASN1_SET:
			return "SET"
		default:
			return fmt.Sprintf("Universal-%d", tag&0x1F)
		}
	} else if tagClass == 2 { // Context
		return fmt.Sprintf("Context[%d]", tag&0x1F)
	} else if tagClass == 1 { // Application
		return fmt.Sprintf("Application[%d]", tag&0x1F)
	} else { // Private
		return fmt.Sprintf("Private[%d]", tag&0x1F)
	}
}
