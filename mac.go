package pkcs12

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509/pkix"
	"hash"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

const (
	sha1Algorithm = "SHA-1"
)

var (
	hashNameByID = map[string]string{
		"1.3.14.3.2.26": sha1Algorithm,
	}
	hashByName = map[string]func() hash.Hash{
		sha1Algorithm: sha1.New,
	}
)

func verifyMac(macData *macData, message, password []byte) error {
	name, ok := hashNameByID[macData.Mac.Algorithm.Algorithm.String()]
	if !ok {
		return UnsupportedFormat("Unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}
	k := deriveMacKeyByAlg[name](macData.MacSalt, password, macData.Iterations)
	password = nil

	mac := hmac.New(hashByName[name], k)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if bytes.Compare(macData.Mac.Digest, expectedMAC) != 0 {
		return PasswordIncorrect("Incorrect password, MAC mismatch")
	}
	return nil
}

// Error indicating that the supplied password is incorrect. Usually, P12/PFX data is signed to be able to verify the password.
type PasswordIncorrect string

func (e PasswordIncorrect) Error() string { return string(e) }
