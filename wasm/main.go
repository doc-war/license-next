//go:build js && wasm

// Package main 浏览器 WASM 入口，编译目标 GOOS=js GOARCH=wasm。
// 暴露给 JavaScript 的函数：
//   encodeCData(license, masterKey) → CData 字符串
//   generateLicenseSign(license, masterKey, privKeyPEM) → JSON 字符串
//
// 编译：GOOS=js GOARCH=wasm go build -o ../official/issuer.wasm .
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/internal/types"
	"github.com/doc-war/license-next/issuer"
)

type signResult struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	CData     string `json:"cdata,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Signature string `json:"signature,omitempty"`
	Lic       string `json:"lic,omitempty"`
}

func main() {
	js.Global().Set("encodeCData", js.FuncOf(encodeCData))
	js.Global().Set("generateLicenseSign", js.FuncOf(generateLicenseSign))
	select {}
}

func encodeCData(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return "参数不足，需要传入 License 对象和 MasterKey"
	}

	masterKey := args[1].String()
	if masterKey == "" {
		return "MasterKey 不能为空"
	}

	jsonStr := js.Global().Get("JSON").Call("stringify", args[0]).String()
	var lic types.License
	if err := json.Unmarshal([]byte(jsonStr), &lic); err != nil {
		return "License 参数解析失败: " + err.Error()
	}

	raw, err := json.Marshal(lic)
	if err != nil {
		return "序列化失败: " + err.Error()
	}

	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{
			1: []byte(masterKey),
		},
	})
	if err != nil {
		return "CKD 初始化失败: " + err.Error()
	}
	cdata, err := c.Derive(raw, "license")
	if err != nil {
		return "CKD 派生失败: " + err.Error()
	}
	return cdata
}

func generateLicenseSign(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return marshalError("参数不足，需要传入 License 对象、MasterKey 和私钥 PEM")
	}

	masterKey := args[1].String()
	if masterKey == "" {
		return marshalError("MasterKey 不能为空")
	}
	privKeyPEM := args[2].String()
	if privKeyPEM == "" {
		return marshalError("私钥不能为空")
	}

	jsonStr := js.Global().Get("JSON").Call("stringify", args[0]).String()
	var lic issuer.License
	if err := json.Unmarshal([]byte(jsonStr), &lic); err != nil {
		return marshalError("License 参数解析失败: " + err.Error())
	}

	iss, err := issuer.New(issuer.Config{
		PrivateKey: privKeyPEM,
		MasterKey:  masterKey,
	})
	if err != nil {
		return marshalError("签发器初始化失败: " + err.Error())
	}

	ls, err := iss.Sign(&lic)
	if err != nil {
		return marshalError("签发失败: " + err.Error())
	}

	licRaw, _ := json.Marshal(ls)

	result := signResult{
		OK:        true,
		CData:     ls.CData,
		Timestamp: ls.Timestamp,
		Signature: ls.Signature,
		Lic:       string(licRaw),
	}
	raw, _ := json.Marshal(result)
	return string(raw)
}

func marshalError(msg string) string {
	raw, _ := json.Marshal(signResult{Error: msg})
	return string(raw)
}