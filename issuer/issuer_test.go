// Package issuer 单元测试
package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/doc-war/license-next/internal/core"
)

const testMasterKey = "01234567890123456789012345678901"

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &priv.PublicKey
}

func privateKeyToPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func TestNew_EmptyPrivateKey(t *testing.T) {
	_, err := New(Config{PrivateKey: "", MasterKey: testMasterKey})
	if err == nil {
		t.Error("expected error for empty private key")
	}
}

func TestNew_EmptyMasterKey(t *testing.T) {
	privPEM := privateKeyToPEM(t, func() *ecdsa.PrivateKey {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return priv
	}())
	_, err := New(Config{PrivateKey: privPEM})
	if err == nil {
		t.Error("expected error for empty master key")
	}
}

func TestNew_InvalidPEM(t *testing.T) {
	_, err := New(Config{PrivateKey: "invalid-pem", MasterKey: testMasterKey})
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, pub := generateTestKey(t)
	privPEM := privateKeyToPEM(t, priv)

	iss, err := New(Config{PrivateKey: privPEM, MasterKey: testMasterKey})
	if err != nil {
		t.Fatal(err)
	}

	lic := &License{
		Customer: "test-customer", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Product: "test-product", MachineID: "test-machine", Features: []string{"feature-a"},
	}

	ls, err := iss.Sign(lic)
	if err != nil {
		t.Fatal(err)
	}

	if ls.CData == "" || ls.Timestamp == 0 || ls.Signature == "" {
		t.Error("all LicenseSign fields should be non-zero")
	}

	if err := core.VerifySignature(pub, ls); err != nil {
		t.Fatal(err)
	}

	decoded, err := core.DecodeLicense(ls.CData, testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Customer != "test-customer" || decoded.Product != "test-product" || decoded.MachineID != "test-machine" {
		t.Error("decoded fields do not match original")
	}
	if len(decoded.Features) != 1 || decoded.Features[0] != "feature-a" {
		t.Errorf("expected Features=[feature-a], got %v", decoded.Features)
	}
}

func TestSignAndVerifyWithCKD(t *testing.T) {
	priv, pub := generateTestKey(t)
	privPEM := privateKeyToPEM(t, priv)

	masterKey := string([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f})

	iss, err := New(Config{PrivateKey: privPEM, MasterKey: masterKey})
	if err != nil {
		t.Fatal(err)
	}

	lic := &License{Customer: "ckd-customer", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "ckd-product", MachineID: "ckd-machine"}

	ls, err := iss.Sign(lic)
	if err != nil {
		t.Fatal(err)
	}

	if err := core.VerifySignature(pub, ls); err != nil {
		t.Fatal(err)
	}

	decoded, err := core.DecodeLicense(ls.CData, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Customer != "ckd-customer" || decoded.Product != "ckd-product" {
		t.Error("CKD round trip decode failed")
	}
}

func TestSignDeterministicCData(t *testing.T) {
	priv, _ := generateTestKey(t)
	privPEM := privateKeyToPEM(t, priv)

	iss, err := New(Config{PrivateKey: privPEM, MasterKey: testMasterKey})
	if err != nil {
		t.Fatal(err)
	}

	lic := &License{Customer: "same", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "same-product", MachineID: "same-machine"}

	ls1, err := iss.Sign(lic)
	if err != nil {
		t.Fatal(err)
	}
	ls2, err := iss.Sign(lic)
	if err != nil {
		t.Fatal(err)
	}

	if ls1.CData != ls2.CData {
		t.Error("CData should be deterministic for same input")
	}
}

func TestSignWithPKCS8Key(t *testing.T) {
	priv, _ := generateTestKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	iss, err := New(Config{PrivateKey: privPEM, MasterKey: testMasterKey})
	if err != nil {
		t.Fatal(err)
	}

	lic := &License{Customer: "pkcs8-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "pkcs8-product", MachineID: "pkcs8-machine"}

	_, err = iss.Sign(lic)
	if err != nil {
		t.Fatal(err)
	}
}