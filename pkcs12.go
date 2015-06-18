// Package pkcs12 provides some implementations of PKCS#12.
//
// This implementation is distilled from https://tools.ietf.org/html/rfc7292 and referenced documents.
// It is intended for decoding P12/PFX-stored certificate+key for use with the crypto/tls package.
package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

var (
	oidDataContentType          = asn1.ObjectIdentifier{1,2,840,113549,1,7,1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1,2,840,113549,1,7,6}
)

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) GetAlgorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}
func (i encryptedContentInfo) GetData() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `ans1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) GetAlgorithm() pkix.AlgorithmIdentifier { return i.AlgorithmIdentifier }
func (i encryptedPrivateKeyInfo) GetData() []byte                        { return i.EncryptedData }

func (i *encryptedPrivateKeyInfo) SetData(data []byte)                    { i.EncryptedData = data }

// PEM block types
const (
	CertificateType = "CERTIFICATE"
	PrivateKeyType  = "PRIVATE KEY"
)

// ConvertToPEM converts all "safe bags" contained in pfxData to PEM blocks.
func ConvertToPEM(pfxData, utf8Password []byte) (blocks []*pem.Block, err error) {
	p, err := bmpString(utf8Password)

	defer func() { // clear out BMP version of the password before we return
		for i := 0; i < len(p); i++ {
			p[i] = 0
		}
	}()

	if err != nil {
		return nil, ErrIncorrectPassword
	}

	bags, p, err := getSafeContents(pfxData, p)

	blocks = make([]*pem.Block, 0, 2)
	for _, bag := range bags {
		var block *pem.Block
		block, err = convertBag(&bag, p)
		if err != nil {
			return
		}
		blocks = append(blocks, block)
	}

	return
}

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	b := new(pem.Block)

	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		if b.Headers == nil {
			b.Headers = make(map[string]string)
		}
		b.Headers[k] = v
	}

	switch {
	case bag.ID.Equal(oidCertBagType):
		b.Type = CertificateType
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, err
		}
		b.Bytes = certsData
	case bag.ID.Equal(oidPkcs8ShroudedKeyBagType):
		b.Type = PrivateKeyType

		key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			b.Bytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			b.Bytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	default:
		return nil, errors.New("don't know how to convert a safe bag of type " + bag.ID.String())
	}
	return b, nil
}

var (
	oidFriendlyName     = asn1.ObjectIdentifier{1,2,840,113549,1,9,20}
	oidLocalKeyID       = asn1.ObjectIdentifier{1,2,840,113549,1,9,21}
	oidMicrosoftCSPName = asn1.ObjectIdentifier{1,3,6,1,4,1,311,17,1}
)

var attributeNameByOID = map[string]string{
	oidFriendlyName.String():     "friendlyName",
	oidLocalKeyID.String():       "localKeyId",
	oidMicrosoftCSPName.String(): "Microsoft CSP Name", // openssl-compatible
}

func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	key = attributeNameByOID[attribute.ID.String()]
	switch {
	case attribute.ID.Equal(oidMicrosoftCSPName):
		fallthrough
	case attribute.ID.Equal(oidFriendlyName):
		if _, err = asn1.Unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return
		}
	case attribute.ID.Equal(oidLocalKeyID):
		id := new([]byte)
		if _, err = asn1.Unmarshal(attribute.Value.Bytes, id); err != nil {
			return
		}
		value = fmt.Sprintf("% x", *id)
	default:
		err = errors.New("don't know how to handle attribute with OID " + attribute.ID.String())
		return
	}

	return key, value, nil
}

// Decode extracts a certificate and private key from pfxData.
// This function assumes that there is only one certificate and only one private key in the pfxData.
func Decode(pfxData, utf8Password []byte) (privateKey interface{}, certificate *x509.Certificate, err error) {
	p, err := bmpString(utf8Password)
	defer func() { // clear out BMP version of the password before we return
		for i := 0; i < len(p); i++ {
			p[i] = 0
		}
	}()

	if err != nil {
		return nil, nil, err
	}
	bags, p, err := getSafeContents(pfxData, p)
	if err != nil {
		return nil, nil, err
	}

	if len(bags) != 2 {
		err = errors.New("expected exactly two safe bags in the PFX PDU")
		return
	}

	for _, bag := range bags {
		switch {
		case bag.ID.Equal(oidCertBagType):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("expected exactly one certificate in the certBag")
				return nil, nil, err
			}
			certificate = certs[0]
		case bag.ID.Equal(oidPkcs8ShroudedKeyBagType):
			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, p); err != nil {
				return nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, errors.New("certificate missing")
	}
	if privateKey == nil {
		return nil, nil, errors.New("private key missing")
	}

	return
}

func getSafeContents(p12Data, password []byte) (bags []safeBag, actualPassword []byte, err error) {
	pfx := new(pfxPdu)
	if _, err = asn1.Unmarshal(p12Data, pfx); err != nil {
		return nil, nil, fmt.Errorf("error reading P12 data: %v", err)
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if _, err = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	actualPassword = password
	password = nil
	if len(pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		if err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, actualPassword); err != nil {
			if err == ErrIncorrectPassword && bytes.Compare(actualPassword, []byte{0, 0}) == 0 {
				// some implementations use an empty byte array for the empty string password
				// try one more time with empty-empty password
				actualPassword = []byte{}
				err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, actualPassword)
			}
		}
		if err != nil {
			return
		}
	}

	var authenticatedSafe []contentInfo
	if _, err = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return
	}

	if len(authenticatedSafe) != 2 {
		return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if _, err = asn1.Unmarshal(ci.Content.Bytes, &data); err != nil {
				return
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if _, err = asn1.Unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return
			}
			if encryptedData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, actualPassword); err != nil {
				return
			}
		default:
			return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if _, err = asn1.Unmarshal(data, &safeContents); err != nil {
			return
		}
		bags = append(bags, safeContents...)
	}
	return
}

// Encode produces pfxData containing one private key, an end-entity certificate, and any number of CA certificates
// It emulates the behavior of OpenSSL's PKCS12_create: it creates two SafeContents: one that's encrypted with RC2
// and contains the certificates, and another that is unencrypted and contains the private key shrouded with 3DES.
// The private key bag and the end-entity certificate bag have the LocalKeyId attribute set to the SHA-1 fingerprint
// of the end-entity certificate.
func Encode (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, utf8Password []byte) (pfxData []byte, err error) {
	p, err := bmpString(utf8Password)

	if err != nil {
		return nil, err
	}

	defer func() { // clear out BMP version of the password before we return
		for i := 0; i < len(p); i++ {
			p[i] = 0
		}
	}()

	var pfx pfxPdu
	pfx.Version = 3

	var certFingerprint = sha1.Sum(certificate.Raw)
	var localKeyIDAttr pkcs12Attribute
	localKeyIDAttr.ID = oidLocalKeyID
	localKeyIDAttr.Value.Class = 0
	localKeyIDAttr.Value.Tag = 17
	localKeyIDAttr.Value.IsCompound = true
	if localKeyIDAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return nil, err
	}

	var certBags []safeBag
	var certBag *safeBag
	if certBag, err = makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIDAttr}); err != nil {
		return nil, err
	}
	certBags = append(certBags, *certBag)

	for _, cert := range caCerts {
		if certBag, err = makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	var keyBag safeBag
	keyBag.ID = oidPkcs8ShroudedKeyBagType
	keyBag.Value.Class = 2
	keyBag.Value.Tag = 0
	keyBag.Value.IsCompound = true
	if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(privateKey, p); err != nil {
		return nil, err
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIDAttr)

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(certBags, p); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents([]safeBag{keyBag}, nil); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pfx.MacData.Mac.Algorithm.Algorithm = oidSha1Algorithm
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = 1
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, p); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, fmt.Errorf("error writing P12 data: %v", err)
	}
	return
}

func makeCertBag (certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.ID = oidCertBagType
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func makeSafeContents (bags []safeBag, password []byte) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if password == nil {
		ci.ContentType = oidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		var randomSalt []byte
		if _, err = rand.Read(randomSalt); err != nil {
			return
		}

		var algo pkix.AlgorithmIdentifier
		algo.Algorithm = oidPbewithSHAAnd40BitRC2CBC
		if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
			return
		}

		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if err = pbEncrypt(&encryptedData.EncryptedContentInfo, data, password); err != nil {
			return
		}

		ci.ContentType = oidEncryptedDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(encryptedData); err != nil {
			return
		}
	}
	return
}
