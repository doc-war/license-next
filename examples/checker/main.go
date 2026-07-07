// Package main 客户端集成示例。
// 通过环境变量 LICENSE_PUBLIC_KEY 传入公钥，LICENSE_MASTER_KEY 传入 MasterKey。
package main

import (
	"log"
	"os"

	licensenext "github.com/doc-war/license-next"
)

func main() {
	pubKey := os.Getenv("LICENSE_PUBLIC_KEY")
	if pubKey == "" {
		log.Fatal("请设置 LICENSE_PUBLIC_KEY 环境变量")
	}
	masterKey := os.Getenv("LICENSE_MASTER_KEY")
	if masterKey == "" {
		log.Fatal("请设置 LICENSE_MASTER_KEY 环境变量")
	}

	checker, err := licensenext.New(licensenext.Config{
		Product:   "myapp",
		PublicKey: pubKey,
		MasterKey: masterKey,
		RemoteURL: "https://license.example.com/v1/query",
	})
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	lic, err := checker.Check()
	if err != nil {
		log.Fatalf("license校验失败: %v", err)
	}

	log.Printf("欢迎 %s，license有效期至 %s", lic.Customer, lic.ExpireAt.Format("2006-01-02"))
	log.Printf("可用功能: %v", lic.Features)
}
