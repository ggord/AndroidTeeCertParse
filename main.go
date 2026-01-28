package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
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
			// Print detailed ASN.1 structure
			fmt.Printf("\n=== Detailed ASN.1 Field Dump ===\n")
			dumpASN1Fields(certData, 0, 0)
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
