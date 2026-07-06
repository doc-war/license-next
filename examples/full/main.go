// Package main 端到端全流程演示：
// 加载密钥 → 签发 License → 验签 → 解码 → 篡改检测 → CKD 确定性测试
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/issuer"
)

const dataDir = "examples/full/testdata"
const testMasterKey = "01234567890123456789012345678901"

var ErrBadSignature = fmt.Errorf("签名验证失败")

type ecdsaSignature struct {
	R, S *big.Int
}

func verifySignature(pub *ecdsa.PublicKey, cdata string, timestamp int64, signature string) error {
	payload := fmt.Sprintf("%s|%d", cdata, timestamp)
	hash := sha256.Sum256([]byte(payload))

	sigRaw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return ErrBadSignature
	}
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(sigRaw, &sig); err != nil {
		return ErrBadSignature
	}
	if !ecdsa.Verify(pub, hash[:], sig.R, sig.S) {
		return ErrBadSignature
	}
	return nil
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("PEM解析失败")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*ecdsa.PublicKey), nil
}

func main() {
	masterKey := os.Getenv("CKD_MASTER_KEY")
	if masterKey == "" {
		masterKey = testMasterKey
		fmt.Printf("  使用测试 MasterKey: %s\n", masterKey)
	}

	fmt.Println("========================================")
	fmt.Println("  license-next 全流程测试")
	fmt.Println("========================================")

	// ---- 1. 加载密钥 ----
	fmt.Println("\n[1/6] 加载ECC密钥...")
	privPEM, err := os.ReadFile(dataDir + "/key-private.pem")
	if err != nil {
		panic(err)
	}
	pub, err := loadPublicKey(dataDir + "/key-public.pem")
	if err != nil {
		panic(err)
	}
	wrongPub, err := loadPublicKey(dataDir + "/key-public-wrong.pem")
	if err != nil {
		panic(err)
	}
	fmt.Println("  私钥: key-private.pem")
	fmt.Println("  公钥: key-public.pem")
	fmt.Println("  错误公钥: key-public-wrong.pem")

	// ---- 2. 签发 License ----
	fmt.Println("\n[2/6] 签发License...")

	iss, err := issuer.New(issuer.Config{
		PrivateKey: string(privPEM),
		MasterKey:  masterKey,
	})
	if err != nil {
		panic(err)
	}

	lic := &issuer.License{
		Customer:  "Acme Corp",
		ExpireAt:  time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
		Product:   "myapp",
		MachineID: "machine-" + fmt.Sprintf("%d", time.Now().Unix()%100000),
		Features:  []string{"premium", "audit-log"},
	}
	ls, err := iss.Sign(lic)
	if err != nil {
		panic(err)
	}

	licJSON, _ := json.MarshalIndent(lic, "  ", "  ")
	fmt.Printf("  License:\n  %s\n", licJSON)
	lsJSON, _ := json.MarshalIndent(ls, "  ", "  ")
	fmt.Printf("  LicenseSign:\n  %s\n", lsJSON)

	// ---- 3. 验签 ----
	fmt.Println("\n[3/6] 验签...")
	if err := verifySignature(pub, ls.CData, ls.Timestamp, ls.Signature); err != nil {
		fmt.Printf("  ❌ 验签失败: %v\n", err)
	} else {
		fmt.Println("  ✅ 验签通过")
	}

	// ---- 4. 解码 CData ----
	fmt.Println("\n[4/6] 解码CData还原License...")
	c, _ := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{1: []byte(masterKey)},
	})
	raw, err := c.Parse(ls.CData, "license")
	if err != nil {
		fmt.Printf("  ❌ CKD解析失败: %v\n", err)
	} else {
		var decoded issuer.License
		json.Unmarshal(raw, &decoded)
		decJSON, _ := json.MarshalIndent(decoded, "  ", "  ")
		fmt.Printf("  CKD解析还原 License:\n  %s\n", decJSON)
	}

	// ---- 5. 篡改检测 ----
	fmt.Println("\n[5/6] 篡改检测...")

	tests := []struct {
		name string
		fn   func() error
	}{
		{"篡改CData", func() error {
			cp := *ls; cp.CData = "AAAAAAAA"
			return verifySignature(pub, cp.CData, cp.Timestamp, cp.Signature)
		}},
		{"篡改Timestamp", func() error {
			cp := *ls; cp.Timestamp = 0
			return verifySignature(pub, cp.CData, cp.Timestamp, cp.Signature)
		}},
		{"错误公钥", func() error {
			return verifySignature(wrongPub, ls.CData, ls.Timestamp, ls.Signature)
		}},
		{"篡改Signature", func() error {
			cp := *ls; cp.Signature = base64.StdEncoding.EncodeToString([]byte("tampered"))
			return verifySignature(pub, cp.CData, cp.Timestamp, cp.Signature)
		}},
	}
	for _, tt := range tests {
		if err := tt.fn(); err != nil {
			fmt.Printf("  ✅ %s → 验签拒绝\n", tt.name)
		} else {
			fmt.Printf("  ❌ %s → 验签通过（异常）\n", tt.name)
		}
	}

	// ---- 6. CKD 确定性 ----
	fmt.Println("\n[6/6] CKD确定性...")
	ls2, _ := iss.Sign(lic)
	if ls.CData == ls2.CData {
		fmt.Println("  ✅ 相同输入 → 相同CData")
	} else {
		fmt.Println("  ❌ 异常: 相同输入 → 不同CData")
	}

	fmt.Println("\n========================================")
	fmt.Println("  全流程测试完成")
	fmt.Println("========================================")
}