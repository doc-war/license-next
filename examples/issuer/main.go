// Package main 服务端签发示例。
// 通过环境变量 ISSUER_PRIVATE_KEY 传入私钥，ISSUER_MASTER_KEY 传入 MasterKey。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/doc-war/license-next/issuer"
)

func main() {
	privKey := os.Getenv("ISSUER_PRIVATE_KEY")
	if privKey == "" {
		log.Fatal("请设置 ISSUER_PRIVATE_KEY 环境变量")
	}

	masterKey := os.Getenv("ISSUER_MASTER_KEY")
	if masterKey == "" {
		log.Fatal("请设置 ISSUER_MASTER_KEY 环境变量")
	}

	iss, err := issuer.New(issuer.Config{
		PrivateKey: privKey,
		MasterKey:  masterKey,
	})
	if err != nil {
		log.Fatalf("签发端初始化失败: %v", err)
	}

	lic := &issuer.License{
		Customer:  "Acme Corp",
		ExpireAt:  time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
		Product:   "myapp",
		MachineID: "target-machine-id",
		Features:  []string{"premium", "audit-log"},
	}

	ls, err := iss.Sign(lic)
	if err != nil {
		log.Fatalf("签发失败: %v", err)
	}

	raw, _ := json.MarshalIndent(ls, "", "  ")
	fmt.Println(string(raw))
}
