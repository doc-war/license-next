package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"unsafe"
	"testing"
	"time"

	"github.com/doc-war/license-next/issuer"
)

func TestSign(t *testing.T) {
	privPEM := generatePrivPEM(t)
	in := signInput{
		PrivateKey: privPEM,
		License: &issuer.License{
			Customer: "test-customer",
			ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			Product:  "test-product", MachineID: "test-machine",
			Features: []string{"feature-a"},
		},
	}
	inputBytes, _ := json.Marshal(in)

	ptr := alloc(uint32(len(inputBytes)))
	copy(unsafeSlice(ptr, len(inputBytes)), inputBytes)
	outLen := sign(ptr, uint32(len(inputBytes)))
	outPtr := getResult()
	if outPtr == nil {
		t.Fatal("getResult returned nil")
	}
	outBytes := unsafeSlice(outPtr, int(outLen))

	var out signOutput
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatalf("输出JSON解析失败: %v", err)
	}
	if !out.OK {
		t.Fatalf("sign 返回错误: %s", out.Error)
	}
	if out.LicenseSign == nil {
		t.Fatal("LicenseSign 为空")
	}
	if out.LicenseSign.CData == "" || out.LicenseSign.Signature == "" || out.LicenseSign.Timestamp == 0 {
		t.Error("LicenseSign 字段不应为空")
	}
}

func TestSign_CKD(t *testing.T) {
	privPEM := generatePrivPEM(t)
	masterKey := "01234567890123456789012345678901"
	in := signInput{
		PrivateKey: privPEM, MasterKey: masterKey,
		License: &issuer.License{
			Customer: "ckd-customer", Product: "ckd-product", MachineID: "ckd-machine",
			ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	inputBytes, _ := json.Marshal(in)

	ptr := alloc(uint32(len(inputBytes)))
	copy(unsafeSlice(ptr, len(inputBytes)), inputBytes)
	outLen := sign(ptr, uint32(len(inputBytes)))

	var out signOutput
	outBytes := unsafeSlice(getResult(), int(outLen))
	json.Unmarshal(outBytes, &out)
	if !out.OK {
		t.Fatalf("CKD sign 返回错误: %s", out.Error)
	}
}

func TestSign_InvalidInput(t *testing.T) {
	in := signInput{PrivateKey: "invalid"}
	inputBytes, _ := json.Marshal(in)
	ptr := alloc(uint32(len(inputBytes)))
	copy(unsafeSlice(ptr, len(inputBytes)), inputBytes)
	outLen := sign(ptr, uint32(len(inputBytes)))

	var out signOutput
	outBytes := unsafeSlice(getResult(), int(outLen))
	json.Unmarshal(outBytes, &out)
	if out.OK {
		t.Error("非法输入应返回错误")
	}
	if out.Error == "" {
		t.Error("错误信息不应为空")
	}
}

func TestIssuerCache(t *testing.T) {
	privPEM := generatePrivPEM(t)

	iss1, err := getIssuer(privPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	iss2, err := getIssuer(privPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	if iss1 != iss2 {
		t.Error("相同密钥应返回同一 issuer 实例")
	}
}

func TestSignDeterministic(t *testing.T) {
	privPEM := generatePrivPEM(t)
	in := signInput{
		PrivateKey: privPEM,
		License: &issuer.License{
			Customer: "same", Product: "same-p", MachineID: "same-m",
			ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	inputBytes, _ := json.Marshal(in)
	ptr := alloc(uint32(len(inputBytes)))
	copy(unsafeSlice(ptr, len(inputBytes)), inputBytes)

	outLen1 := sign(ptr, uint32(len(inputBytes)))
	var out1 signOutput
	json.Unmarshal(unsafeSlice(getResult(), int(outLen1)), &out1)

	outLen2 := sign(ptr, uint32(len(inputBytes)))
	var out2 signOutput
	json.Unmarshal(unsafeSlice(getResult(), int(outLen2)), &out2)

	if out1.LicenseSign.CData != out2.LicenseSign.CData {
		t.Error("相同输入应产生相同 CData")
	}
}

func unsafeSlice(ptr *uint8, n int) []byte {
	return unsafe.Slice(ptr, n)
}

func generatePrivPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}
