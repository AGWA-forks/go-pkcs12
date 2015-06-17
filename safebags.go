package pkcs12

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

//see https://tools.ietf.org/html/rfc7292#appendix-D
var (
	oidKeyBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,1}
	oidPkcs8ShroudedKeyBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,2}
	oidCertBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,3}
	oidCrlBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,4}
	oidSecretBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,5}
	oidSafeContentsBagType = asn1.ObjectIdentifier{1,2,840,113549,1,12,10,1,6}
)

var (
	oidCertTypeX509Certificate = asn1.ObjectIdentifier{1,2,840,113549,1,9,22,1}
	oidLocalKeyIDAttribute     = asn1.ObjectIdentifier{1,2,840,113549,1,9,21}
)

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if _, err = asn1.Unmarshal(asn1Data, pkinfo); err != nil {
		err = fmt.Errorf("error decoding PKCS8 shrouded key bag: %v", err)
		return nil, err
	}

	pkData, err := pbDecrypt(pkinfo, password)
	if err != nil {
		err = fmt.Errorf("error decrypting PKCS8 shrouded key bag: %v", err)
		return
	}

	rv := new(asn1.RawValue)
	if _, err = asn1.Unmarshal(pkData, rv); err != nil {
		err = fmt.Errorf("could not decode decrypted private key data")
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		err = fmt.Errorf("error parsing PKCS8 private key: %v", err)
		return nil, err
	}
	return
}

func encodePkcs8ShroudedKeyBag(privateKey interface{}, password []byte) (asn1Data []byte, err error) {
	var pkData []byte
	if pkData, err = marshalPKCS8PrivateKey(privateKey); err != nil {
		return
	}

	var randomSalt []byte
	if _, err = rand.Read(randomSalt); err != nil {
		return
	}
	var paramBytes []byte
	if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
		return
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = oidPbeWithSHAAnd3KeyTripleDESCBC
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		err = fmt.Errorf("error encrypting PKCS8 shrouded key bag: %v", err)
		return
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		err = fmt.Errorf("error encoding cert bag: %v", err)
		return
	}
	return
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if _, err := asn1.Unmarshal(asn1Data, bag); err != nil {
		err = fmt.Errorf("error decoding cert bag: %v", err)
		return nil, err
	}
	if !bag.ID.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.ID = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		err = fmt.Errorf("error encoding cert bag: %v", err)
		return
	}
	return
}
