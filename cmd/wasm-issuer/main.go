// Package main 是 WASM 签发入口，供 Cloudflare Workers 通过 wasip1 导入。
//
// 编译：GOOS=wasip1 GOARCH=wasm go build -o ../../worker/issuer.wasm .
//
// JS 调用流程：
//   1. alloc(inputLen) → 获取输入缓冲区指针
//   2. 将 JSON 写入 WASM 线性内存
//   3. sign(ptr, len) → 返回输出长度
//   4. getResult() → 获取输出缓冲区指针
//   5. 从 WASM 线性内存读取结果 JSON
package main

import (
	"encoding/json"
	"unsafe"

	"github.com/doc-war/license-next/issuer"
)

// signInput wasm sign 函数的输入结构
type signInput struct {
	PrivateKey string         `json:"private_key"`
	MasterKey  string         `json:"master_key"`
	License    *issuer.License `json:"license"`
}

// signOutput wasm sign 函数的输出结构
type signOutput struct {
	OK          bool               `json:"ok"`
	LicenseSign *issuer.LicenseSign `json:"license_sign,omitempty"`
	Error       string             `json:"error,omitempty"`
}

var (
	resultBuf       []byte           // sign 输出的字节缓冲区
	cachedPrivKey   string           // 缓存的私钥，避免重复解析 PEM
	cachedMasterKey string           // 缓存的 master key
	cachedIssuer    *issuer.Issuer   // 缓存的签发器实例
)

//go:wasmexport alloc
func alloc(size uint32) *uint8 {
	buf := make([]byte, size)
	return &buf[0]
}

//go:wasmexport getResult
func getResult() *uint8 {
	if len(resultBuf) == 0 {
		return nil
	}
	return &resultBuf[0]
}

//go:wasmexport sign
func sign(inputPtr *uint8, inputLen uint32) uint32 {
	inputBytes := unsafe.Slice(inputPtr, int(inputLen))
	var in signInput
	if err := json.Unmarshal(inputBytes, &in); err != nil {
		return packError("解析输入失败: " + err.Error())
	}

	iss, err := getIssuer(in.PrivateKey, in.MasterKey)
	if err != nil {
		return packError("初始化签发器失败: " + err.Error())
	}

	ls, err := iss.Sign(in.License)
	if err != nil {
		return packError("签发失败: " + err.Error())
	}

	out := signOutput{OK: true, LicenseSign: ls}
	raw, _ := json.Marshal(out)
	resultBuf = raw
	return uint32(len(raw))
}

// getIssuer 返回缓存的签发器，若密钥变更则重新创建
func getIssuer(privKey, masterKey string) (*issuer.Issuer, error) {
	if privKey == cachedPrivKey && masterKey == cachedMasterKey && cachedIssuer != nil {
		return cachedIssuer, nil
	}
	iss, err := issuer.New(issuer.Config{
		PrivateKey: privKey,
		MasterKey:  masterKey,
	})
	if err != nil {
		return nil, err
	}
	cachedPrivKey = privKey
	cachedMasterKey = masterKey
	cachedIssuer = iss
	return iss, nil
}

// packError 将错误信息写入 resultBuf 并返回长度
func packError(msg string) uint32 {
	out := signOutput{Error: msg}
	raw, _ := json.Marshal(out)
	resultBuf = raw
	return uint32(len(raw))
}

func main() {}
