// Package issuer 是服务端签发 License 的工具包。
// 包含 ECDSA 签名、CKD 派生等逻辑。
// 客户端应用不应 import 此包。
package issuer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/internal/types"
)

// License 授权合同（类型别名，与 types.License 一致）
type License = types.License
// LicenseSign 签名结果（类型别名）
type LicenseSign = types.LicenseSign

// Config 签发端配置
type Config struct {
	PrivateKey string // 必填，PEM 格式的 ECC 私钥（支持 SEC1 和 PKCS8）
	MasterKey  string // 必填，CKD MasterKey
}

// Issuer 签发器，持有私钥和可选的 CKD 实例
type Issuer struct {
	privateKey *ecdsa.PrivateKey // ECDSA P-256 私钥
	ckd        ckd.CKD           // CKD 派生器（未设置时为零值，Sign 中判断 nil）
}

// ecdsaSignature 用于 ASN.1 序列化 ECDSA 签名 (R, S)
type ecdsaSignature struct {
	R, S *big.Int
}

// New 创建 Issuer，解析私钥并初始化 CKD
func New(cfg Config) (*Issuer, error) {
	if cfg.PrivateKey == "" {
		return nil, errors.New("issuer: PrivateKey 不能为空")
	}
	if cfg.MasterKey == "" {
		return nil, errors.New("issuer: MasterKey 不能为空")
	}

	priv, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}

	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{
			1: []byte(cfg.MasterKey),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("issuer: CKD初始化失败: %w", err)
	}

	return &Issuer{privateKey: priv, ckd: c}, nil
}

// parsePrivateKey 解析 PEM 格式的 ECDSA 私钥。
// 兼容 SEC1（EC PRIVATE KEY）和 PKCS8（PRIVATE KEY）两种格式，
// 并自动跳过 OpenSSL 输出的 EC PARAMETERS 块。
func parsePrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	raw := []byte(pemStr)
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("issuer: 私钥PEM解析失败")
		}
		// 跳过 EC PARAMETERS 块（OpenSSL 有时会在私钥前输出该块）
		if block.Type == "EC PARAMETERS" {
			raw = rest
			continue
		}
		// 尝试 SEC1 格式
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		// 尝试 PKCS8 格式
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("issuer: 私钥类型非ECC")
			}
			return ecKey, nil
		}
		raw = rest
	}
}

// Sign 对 License 进行签名。
// 1. 序列化 License 为 JSON
// 2. 使用 CKD Derive 生成 CData
// 3. 计算 SHA256(CData + "|" + Timestamp) 并用 ECDSA 签名
// 4. 返回 LicenseSign
func (iss *Issuer) Sign(lic *License) (*LicenseSign, error) {
	raw, err := json.Marshal(lic)
	if err != nil {
		return nil, fmt.Errorf("issuer: License序列化失败: %w", err)
	}

	cdata, err := iss.ckd.Derive(raw, "license")
	if err != nil {
		return nil, fmt.Errorf("issuer: CKD派生失败: %w", err)
	}

	// 签名
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s|%d", cdata, timestamp)
	hash := sha256.Sum256([]byte(payload))

	r, s, err := ecdsa.Sign(rand.Reader, iss.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("issuer: 签名失败: %w", err)
	}

	sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("issuer: 签名编码失败: %w", err)
	}

	return &types.LicenseSign{
		CData:     cdata,
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}
