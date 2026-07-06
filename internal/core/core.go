// Package core 封装了 license-next 所有客户端核心逻辑，
// 包括：错误定义、机器码获取、Base64 编解码。
// 这些功能被 root package（licensenext）调用，不对外暴露。
package core

import (
	"encoding/base64"
	"errors"

	"github.com/denisbrodbeck/machineid"
)

var (
	ErrBadSignature    = errors.New("licensenext: 签名验证失败")
	ErrMachineID       = errors.New("licensenext: 机器码不匹配")
	ErrExpired         = errors.New("licensenext: license已过期")
	ErrProductMismatch = errors.New("licensenext: 产品不匹配")
)

// GetMachineID 基于应用名返回绑定的机器码（通过 machineid 库获取硬件信息后加盐哈希）
func GetMachineID(appName string) (string, error) {
	return machineid.ProtectedID(appName)
}

// B64Encode 使用 URL-safe base64 编码
func B64Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// B64Decode 解码 URL-safe base64
func B64Decode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}
