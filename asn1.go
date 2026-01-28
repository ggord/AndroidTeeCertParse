package main

import (
	"fmt"
)

// ASN.1 Tag Types
const (
	ASN1_BOOLEAN           = 0x01
	ASN1_INTEGER           = 0x02
	ASN1_BIT_STRING        = 0x03
	ASN1_OCTET_STRING      = 0x04
	ASN1_NULL              = 0x05
	ASN1_OBJECT_IDENTIFIER = 0x06
	ASN1_ENUMERATED        = 0x0A
	ASN1_UTF8_STRING       = 0x0C
	ASN1_PRINTABLE_STRING  = 0x13
	ASN1_IA5_STRING        = 0x16
	ASN1_UTCTIME           = 0x17
	ASN1_GENERALIZEDTIME   = 0x18
	ASN1_SEQUENCE          = 0x30
	ASN1_SET               = 0x31
)

// Keymaster Tag Numbers
const (
	KM_TAG_PURPOSE                     = 1
	KM_TAG_ALGORITHM                   = 2
	KM_TAG_KEY_SIZE                    = 3
	KM_TAG_DIGEST                      = 5
	KM_TAG_EC_CURVE                    = 10
	KM_TAG_NO_AUTH_REQUIRED            = 503
	KM_TAG_ORIGIN                      = 702
	KM_TAG_CREATION_DATETIME           = 701
	KM_TAG_ROOT_OF_TRUST               = 704
	KM_TAG_OS_VERSION                  = 705
	KM_TAG_OS_PATCHLEVEL               = 706
	KM_TAG_ATTESTATION_APPLICATION_ID  = 709
	KM_TAG_VENDOR_PATCHLEVEL           = 718
	KM_TAG_BOOT_PATCHLEVEL             = 719
)

// TEE Attestation OID: 1.3.6.1.4.1.11129.2.1.17
var TEE_ATTESTATION_OID = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11}

// ASN1Element represents a parsed ASN.1 element
type ASN1Element struct {
	Tag       byte
	TagSize   int
	TagNumber uint32
	Length    uint32
	Data      []byte
	Offset    int
}

// ParseASN1Element parses an ASN.1 element from data at the given offset
func ParseASN1Element(data []byte, offset int) (*ASN1Element, error) {
	if offset >= len(data) {
		return nil, fmt.Errorf("offset %d is beyond data length %d", offset, len(data))
	}

	elem := &ASN1Element{
		Data:   data,
		Offset: offset,
	}

	// Parse tag
	elem.Tag = data[offset]
	elem.TagSize = 1

	// Check if this is an extended tag (tag number >= 31)
	if (elem.Tag & 0x1F) == 0x1F {
		// Extended tag number: multi-byte BER encoding
		elem.TagNumber = 0
		current := offset + 1
		for {
			if current >= len(data) {
				return nil, fmt.Errorf("unexpected end of data while parsing extended tag")
			}
			b := data[current]
			elem.TagNumber = (elem.TagNumber << 7) | uint32(b&0x7F)
			elem.TagSize++
			current++
			if (b & 0x80) == 0 {
				break
			}
		}
	} else {
		// Simple tag number
		elem.TagNumber = uint32(elem.Tag & 0x1F)
	}

	// Parse length
	lengthOffset := offset + elem.TagSize
	if lengthOffset >= len(data) {
		return nil, fmt.Errorf("unexpected end of data while parsing length")
	}

	firstLengthByte := data[lengthOffset]
	lengthSize := 1

	if (firstLengthByte & 0x80) == 0 {
		// Short form: length is directly in the first byte
		elem.Length = uint32(firstLengthByte)
	} else {
		// Long form: first byte's low 7 bits indicate number of subsequent length bytes
		numOctets := int(firstLengthByte & 0x7F)
		if numOctets == 0 {
			// Indefinite length (0x80), not supported in DER
			elem.Length = 0
		} else if numOctets > 0 && numOctets <= 4 {
			elem.Length = 0
			for i := 0; i < numOctets; i++ {
				if lengthOffset+1+i >= len(data) {
					return nil, fmt.Errorf("unexpected end of data while parsing length")
				}
				elem.Length = (elem.Length << 8) | uint32(data[lengthOffset+1+i])
			}
			lengthSize += numOctets
		} else {
			return nil, fmt.Errorf("invalid length encoding: numOctets=%d", numOctets)
		}
	}

	// Validate that we have enough data
	contentOffset := offset + elem.TagSize + lengthSize
	if contentOffset+int(elem.Length) > len(data) {
		return nil, fmt.Errorf("content length %d exceeds available data", elem.Length)
	}

	return elem, nil
}

// GetTagClass returns the tag class (0=Universal, 1=Application, 2=Context, 3=Private)
func (e *ASN1Element) GetTagClass() byte {
	return (e.Tag >> 6) & 0x03
}

// IsConstructed returns true if this is a constructed element
func (e *ASN1Element) IsConstructed() bool {
	return (e.Tag & 0x20) != 0
}

// GetContentOffset returns the offset to the content (after tag and length)
func (e *ASN1Element) GetContentOffset() int {
	// Calculate length field size
	lengthOffset := e.Offset + e.TagSize
	firstLengthByte := e.Data[lengthOffset]
	lengthSize := 1
	if (firstLengthByte & 0x80) != 0 {
		numOctets := int(firstLengthByte & 0x7F)
		lengthSize += numOctets
	}
	return e.Offset + e.TagSize + lengthSize
}

// GetContent returns the content bytes
func (e *ASN1Element) GetContent() []byte {
	contentOffset := e.GetContentOffset()
	return e.Data[contentOffset : contentOffset+int(e.Length)]
}

// GetNextOffset returns the offset to the next element (after this element's content)
func (e *ASN1Element) GetNextOffset() int {
	return e.GetContentOffset() + int(e.Length)
}

// GetIntegerValue parses the element as an INTEGER
// Note: This implementation only handles unsigned integers (positive values)
// which is sufficient for TEE certificates where all integer fields are positive
func (e *ASN1Element) GetIntegerValue() uint64 {
	if e.Tag != ASN1_INTEGER || e.Length == 0 {
		return 0
	}
	content := e.GetContent()
	var value uint64
	for _, b := range content {
		value = (value << 8) | uint64(b)
	}
	return value
}

// GetEnumeratedValue parses the element as an ENUMERATED
func (e *ASN1Element) GetEnumeratedValue() byte {
	if e.Tag != ASN1_ENUMERATED || e.Length == 0 {
		return 0
	}
	content := e.GetContent()
	return content[0]
}

// GetBooleanValue parses the element as a BOOLEAN
func (e *ASN1Element) GetBooleanValue() bool {
	if e.Tag != ASN1_BOOLEAN || e.Length == 0 {
		return false
	}
	content := e.GetContent()
	return content[0] != 0
}
