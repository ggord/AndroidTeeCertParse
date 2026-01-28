package main

// SecurityLevel represents the security level enumeration
type SecurityLevel byte

const (
	SecurityLevelSoftware   SecurityLevel = 0
	SecurityLevelTEE        SecurityLevel = 1
	SecurityLevelStrongBox  SecurityLevel = 2
	SecurityLevelUnknown    SecurityLevel = 255
)

// RootOfTrust represents the Root of Trust structure
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState uint32 // 0=Verified, 1=Self-Signed, 2=Unverified, 3=Failed
}

// PackageInfo represents application package information
type PackageInfo struct {
	PackageName string
	VersionCode uint32
}

// AttestationApplicationId represents the attestation application ID
type AttestationApplicationId struct {
	PackageInfos      []PackageInfo
	SignatureDigests  [][]byte // SHA-256 digests
}

// AuthorizationList represents the parsed authorization list
type AuthorizationList struct {
	Purposes            []string
	Algorithm           uint32
	KeySize             uint32
	Digests             []string
	ECCurve             uint32
	NoAuthRequired      bool
	Origin              uint32
	CreationDateTime    uint64
	RootOfTrust         RootOfTrust
	OSVersion           uint32
	OSPatchLevel        uint32
	VendorPatchLevel    uint32
	BootPatchLevel      uint32
	AttestationAppId    AttestationApplicationId
}

// AttestationRecord represents the TEE attestation record
type AttestationRecord struct {
	AttestationVersion      uint32
	AttestationSecurityLevel SecurityLevel
	KeymasterVersion        uint32
	KeymasterSecurityLevel  SecurityLevel
	AttestationChallenge    []byte
	UniqueId                []byte
	SoftwareEnforced        *AuthorizationList
	TEEEnforced             *AuthorizationList
}

// TEEAttestationExtension represents the TEE attestation extension
type TEEAttestationExtension struct {
	AttestationRecord *AttestationRecord
}

// CertificateExtensions represents the X.509 extensions
type CertificateExtensions struct {
	TEEExtension *TEEAttestationExtension
}

// Name represents a Distinguished Name (DN)
type Name struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
}

// Validity represents the validity period
type Validity struct {
	NotBefore string
	NotAfter  string
}

// PublicKeyInfo represents public key information
type PublicKeyInfo struct {
	Algorithm string
	KeySize   int
}

// TBSCertificate represents the "To Be Signed" certificate
type TBSCertificate struct {
	Version      int
	SerialNumber []byte
	Issuer       Name
	Subject      Name
	Validity     Validity
	PublicKey    PublicKeyInfo
	Extensions   *CertificateExtensions
}

// X509Certificate represents the X.509 certificate
type X509Certificate struct {
	TBSCert *TBSCertificate
}

// TeeCert represents the TEE certificate wrapper
type TeeCert struct {
	X509Cert *X509Certificate
	Data     []byte
}
