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
	flag.Parse()

	// If hex string provided, parse it
	if *hexStr != "" {
		parseCertFromHex(*hexStr)
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
		parseCertFromFile(certPath)
	}

	fmt.Printf("\n======================\n")
	os.Exit(0)
}

func parseCertFromHex(hexStr string) {
	fmt.Printf("\n======================\n")
	fmt.Printf("Parsing certificate from hex string\n")
	fmt.Printf("======================\n")

	// Decode hex string
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatalf("[Native-TEE] Error: Failed to decode hex string: %v", err)
	}

	// Parse certificate chain (may contain multiple certificates)
	parseCertificateChain(data)
}

func parseCertificateChain(data []byte) {
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

func parseCertFromFile(certPath string) {
	fmt.Printf("\n======================\n")
	fmt.Printf("Parsing certificate: %s\n", certPath)
	fmt.Printf("======================\n")

	cert, err := NewTeeCertFromFile(certPath)
	if err != nil {
		log.Printf("[Native-TEE] Error: Invalid certificate file or parsing failed: %v", err)
		return
	}

	printCertificateInfo(cert)
}

func printCertificateInfo(cert *TeeCert) {
	fmt.Println("[Native-TEE] Certificate parsed successfully!")

	// Get attestation record with nil checks
	if cert.X509Cert == nil || cert.X509Cert.TBSCert == nil ||
		cert.X509Cert.TBSCert.Extensions == nil ||
		cert.X509Cert.TBSCert.Extensions.TEEExtension == nil ||
		cert.X509Cert.TBSCert.Extensions.TEEExtension.AttestationRecord == nil {
		log.Printf("[Native-TEE] Note: This is a standard X.509 certificate without TEE attestation extension (likely root/intermediate certificate)")
		return
	}

	attestationRecord := cert.X509Cert.TBSCert.Extensions.TEEExtension.AttestationRecord

	// Print Keymaster Security Level
	fmt.Printf("KeymasterSecurityLevel: %d\n", attestationRecord.AttestationSecurityLevel)

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
		fmt.Printf("device_locked: %v\n", rootOfTrust.DeviceLocked)
		fmt.Printf("verified_boot_key size: %d\n", len(rootOfTrust.VerifiedBootKey))
		if len(rootOfTrust.VerifiedBootKey) >= 8 {
			fmt.Printf("verified_boot_key (first 8 bytes): %02X %02X %02X %02X %02X %02X %02X %02X\n",
				rootOfTrust.VerifiedBootKey[0], rootOfTrust.VerifiedBootKey[1],
				rootOfTrust.VerifiedBootKey[2], rootOfTrust.VerifiedBootKey[3],
				rootOfTrust.VerifiedBootKey[4], rootOfTrust.VerifiedBootKey[5],
				rootOfTrust.VerifiedBootKey[6], rootOfTrust.VerifiedBootKey[7])
		}
		fmt.Printf("verified_boot_state: %d\n", rootOfTrust.VerifiedBootState)
	} else {
		fmt.Println("RootOfTrust: Not found")
	}

	// Print OS Version and Patch Levels
	if attestationRecord.SoftwareEnforced != nil {
		if attestationRecord.SoftwareEnforced.OSVersion > 0 {
			fmt.Printf("OSVersion (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.OSVersion)
		}
		if attestationRecord.SoftwareEnforced.OSPatchLevel > 0 {
			fmt.Printf("OSPatchLevel (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.OSPatchLevel)
		}
		if attestationRecord.SoftwareEnforced.BootPatchLevel > 0 {
			fmt.Printf("BootPatchLevel (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.BootPatchLevel)
		}
	}
	if attestationRecord.TEEEnforced != nil {
		if attestationRecord.TEEEnforced.OSVersion > 0 {
			fmt.Printf("OSVersion (TEE Enforced): %d\n", attestationRecord.TEEEnforced.OSVersion)
		}
		if attestationRecord.TEEEnforced.OSPatchLevel > 0 {
			fmt.Printf("OSPatchLevel (TEE Enforced): %d\n", attestationRecord.TEEEnforced.OSPatchLevel)
		}
		if attestationRecord.TEEEnforced.BootPatchLevel > 0 {
			fmt.Printf("BootPatchLevel (TEE Enforced): %d\n", attestationRecord.TEEEnforced.BootPatchLevel)
		}
	}
}
