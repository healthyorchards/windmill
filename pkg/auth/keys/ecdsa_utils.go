package keys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
)

func PemEncodePublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	if encoded, err := x509.MarshalPKIXPublicKey(pubKey); err != nil {
		return "", err
	} else {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
	}
}

func PemDecodePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	decoded, _ := pem.Decode([]byte(pubKey))
	keyBytes := decoded.Bytes
	if publicKey, err := x509.ParsePKIXPublicKey(keyBytes); err != nil {
		return nil, err
	} else {
		return publicKey.(*ecdsa.PublicKey), nil
	}
}

func PemEncodePrivateKey(pvKey *ecdsa.PrivateKey) (string, error) {
	if encoded, err := x509.MarshalECPrivateKey(pvKey); err != nil {
		return "", err
	} else {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), nil
	}
}

func PemDecodePrivateKey(pvKey string) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode([]byte(pvKey))
	keyBytes := decoded.Bytes
	if privateKey, err := x509.ParseECPrivateKey(keyBytes); err != nil {
		return nil, err
	} else {
		return privateKey, nil
	}
}

func ReadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if k, err := PemDecodePrivateKey(string(content)); err != nil {
		return nil, err
	} else {
		return k, nil
	}
}

func ReadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if k, err := PemDecodePublicKey(string(content)); err != nil {
		return nil, err
	} else {
		return k, nil
	}
}

func ReadRemotePublicKey(url string) (*ecdsa.PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	key, err := ioutil.ReadAll(resp.Body)

	if k, err := PemDecodePublicKey(string(key)); err != nil {
		return nil, err
	} else {
		return k, nil
	}
}
