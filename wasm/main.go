//go:build js && wasm

// Package main 浏览器 WASM 入口，编译目标 GOOS=js GOARCH=wasm。
// 暴露 encodeCData(license, masterKey?) 给 JavaScript，返回 CData 字符串。
//
// 编译：GOOS=js GOARCH=wasm go build -o ../official/issuer.wasm .
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/internal/types"
)

func main() {
	js.Global().Set("encodeCData", js.FuncOf(encodeCData))
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