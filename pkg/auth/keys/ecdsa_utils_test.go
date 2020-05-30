package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPemEncodePublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal()
	}
	firstEncode := hex.EncodeToString(elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y))

	encoded, err := PemEncodePublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal()
	}

	assert.NotEmpty(t, encoded)

	otherPK, err := PemDecodePublicKey(encoded)
	if err != nil {
		t.Fatal()
	}

	secondEncode := hex.EncodeToString(elliptic.Marshal(otherPK.Curve, otherPK.X, otherPK.Y))

	assert.Equal(t, firstEncode, secondEncode)
}

func TestPemEncodePrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal()
	}
	firstEncode := hex.EncodeToString(elliptic.Marshal(key.Curve, key.X, key.Y))

	encoded, err := PemEncodePrivateKey(key)
	if err != nil {
		t.Fatal()
	}

	assert.NotEmpty(t, encoded)

	otherPK, err := PemDecodePrivateKey(encoded)
	if err != nil {
		t.Fatal()
	}

	secondEncode := hex.EncodeToString(elliptic.Marshal(otherPK.Curve, otherPK.X, otherPK.Y))

	assert.Equal(t, firstEncode, secondEncode)
}
