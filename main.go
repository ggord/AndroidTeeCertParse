package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	// List of certificate paths to parse
	certPaths := []string{
		// "assests/cert_k30pro.bin",
		"assests/cert_oneplus.bin",
		// "assests/cert_pixel4.bin",
		// "assests/cert_pixel6.bin",
		// "assests/cert_xiaomi6x.bin",
	}

	for _, certPath := range certPaths {
		fmt.Printf("\n======================\n")
		fmt.Printf("Parsing certificate: %s\n", certPath)
		fmt.Printf("======================\n")

		cert, err := NewTeeCertFromFile(certPath)
		if err != nil {
			log.Printf("[Native-TEE] Error: Invalid certificate file or parsing failed: %v", err)
			continue
		}

		fmt.Println("[Native-TEE] Certificate parsed successfully!")

		// Get attestation record
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
			fmt.Printf("OSVersion (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.OSVersion)
			fmt.Printf("OSPatchLevel (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.OSPatchLevel)
			fmt.Printf("BootPatchLevel (Software Enforced): %d\n", attestationRecord.SoftwareEnforced.BootPatchLevel)
		}
		if attestationRecord.TEEEnforced != nil {
			fmt.Printf("OSVersion (TEE Enforced): %d\n", attestationRecord.TEEEnforced.OSVersion)
			fmt.Printf("OSPatchLevel (TEE Enforced): %d\n", attestationRecord.TEEEnforced.OSPatchLevel)
			fmt.Printf("BootPatchLevel (TEE Enforced): %d\n", attestationRecord.TEEEnforced.BootPatchLevel)
		}
	}

	fmt.Printf("\n======================\n")
	os.Exit(0)
}
