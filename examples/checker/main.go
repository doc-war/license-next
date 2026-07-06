// Package main 客户端集成示例。
// 通过环境变量 LICENSE_PUBLIC_KEY 传入公钥，初始化 Checker 并校验 License。
package main

import (
	"context"
	"log"
	"os"

	licensenext "github.com/doc-war/license-next"
)

func main() {
	pubKey := os.Getenv("LICENSE_PUBLIC_KEY")
	if pubKey == "" {
		log.Fatal("请设置 LICENSE_PUBLIC_KEY 环境变量")
	}

	// 初始化 Checker，只需传入公钥和产品名
	checker, err := licensenext.New(licensenext.Config{
		Product:   "myapp",
		PublicKey: pubKey,
		RemoteURL: "https://license.example.com/v1/query",
	})
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	// 校验 License
	lic, err := checker.Check(context.Background())
	if err != nil {
		log.Fatalf("license校验失败: %v", err)
	}

	// 输出欢迎信息和可用功能
	log.Printf("欢迎 %s，license有效期至 %s", lic.Customer, lic.ExpireAt.Format("2006-01-02"))
	log.Printf("可用功能: %v", lic.Features)
}
