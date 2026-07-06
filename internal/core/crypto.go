// Package core 的密码学相关函数：
// ECDSA P-256 公钥解析、签名验证、CData 解码（含 CKD 路径）。
package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/internal/types"
)

// ecdsaSignature 用于 ASN.1 反序列化 ECDSA 签名中的 (R, S) 对
type ecdsaSignature struct {
	R, S *big.Int
}

// ParsePublicKey 解析 PEM 格式的 ECDSA P-256 公钥
func ParsePublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("licensenext: 公钥PEM解析失败")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("licensenext: 公钥类型非ECC")
	}
	return ecPub, nil
}

// VerifySignature 验证 LicenseSign 的 ECDSA 签名。
// 签名字段 = SHA256(CData + "|" + Timestamp)，ASN.1 DER 编码，base64 StdEncoding。
func VerifySignature(pub *ecdsa.PublicKey, ls *types.LicenseSign) error {
	payload := fmt.Sprintf("%s|%d", ls.CData, ls.Timestamp)
	hash := sha256.Sum256([]byte(payload))

	sigRaw, err := base64.StdEncoding.DecodeString(ls.Signature)
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

/*
服务端签发 License 时生成 CData 的流程：

  1. 序列化 License 为 JSON
     raw, _ := json.Marshal(lic)

  2. 使用 CKD 派生，purpose 为 "license"
     c, _ := ckd.New(ckd.Config{
         CurrentVersion: 1,
         SecretsByVersion: map[uint8][]byte{
             1: []byte(masterKey),
         },
     })
     cdata, _ := c.Derive(raw, "license")

  3. 构造 LicenseSign
     sign, _ := ecdsaSign(priv, cdata+"|"+timestamp)
     ls := LicenseSign{
         CData:     cdata,
         Timestamp: time.Now().Unix(),
         Signature: sign,
     }

CData 是 CKD 派生后的外部标识，不暴露 License 合同明文。
旧版本客户端（未配置 MasterKey）使用 base64url 直接解码 CData，
新版本客户端配置 MasterKey 后使用 CKD.Parse 还原。
两种路径的前向兼容由服务端保证：无论客户端是否启用 CKD，
CData 字段格式不变，服务端返回相同的 LicenseSign 结构。
*/

// DecodeLicense 使用 CKD 将 CData 还原为 License 明文。
func DecodeLicense(cdata, masterKey string) (*types.License, error) {
	raw, err := ckdDecode(cdata, masterKey)
	if err != nil {
		return nil, err
	}
	var lic types.License
	if err := json.Unmarshal(raw, &lic); err != nil {
		return nil, err
	}
	return &lic, nil
}

// ckdDecode 使用 CKD 解析 CData，purpose 固定为 "license"
func ckdDecode(cdata, masterKey string) ([]byte, error) {
	secret := []byte(masterKey)
	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{
			1: secret,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("licensenext: CKD初始化失败: %w", err)
	}
	raw, err := c.Parse(cdata, "license")
	if err != nil {
		return nil, fmt.Errorf("licensenext: CData解析失败: %w", err)
	}
	return raw, nil
}
