# license-next

轻量级客户端 License 验证框架，将 issuer（服务端签发）与 checker（客户端校验）分离。

## 架构

```
┌─────────────────────────────────────────────────────────┐
│           开发者（浏览器 / CLI）                          │
│  official/issuer.html → WASM encodeCData → CData 字符串  │
└──────────────────────┬──────────────────────────────────┘
                       │ 手动复制
                       ▼
┌─────────────────────────────────────────────────────────┐
│           Cloudflare Worker（开发者自行部署）               │
│                                                         │
│  KV: key=machine_id, value=CData                        │
│                                                         │
│  GET /v1/query?machine_id=xxx                           │
│    1. 从 KV 读取 CData                                   │
│    2. Web Crypto ECDSA P-256 签名                        │
│    3. 返回 LicenseSign JSON                             │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│           客户端（Go 应用）                                │
│  licensenext.New(cfg) → Check(ctx)                      │
│    1. 本地缓存校验（签名 / 机器码 / 过期 / 产品）          │
│    2. 新鲜度过期 → GET /v1/query 联网刷新                 │
│    3. 异步预刷新（3 天节流）                               │
└─────────────────────────────────────────────────────────┘
```

## 核心概念

### CData — License 编码字符串

CData 是 License 合同明文经过 CKD 协议编码后的字符串，使用 MasterKey 派生，可逆、无状态、不暴露明文。

客户端配置相同的 MasterKey，通过 CKD.Parse 即可解码还原 License。

### License — 授权合同

```go
type License struct {
    Customer         string    // 客户标识（机器码匹配依据）
    CustomerNickname string    // 客户昵称（仅前台反显，可选）
    CustomerEmail    string    // 客户邮箱（仅前台反显，可选）
    ExpireAt         time.Time // 过期时间
    Product          string    // 产品名
    Features         []string  // 功能列表（可选）
    MachineID        string    // 绑定的机器码
}
```

### LicenseSign — 签名结构

```json
{
  "c_data":    "CKD 编码的 License",
  "timestamp": 1750000000,
  "signature": "ECDSA P-256 ASN.1 DER base64 签名",
  "revoked":   false
}
```

签名覆盖 `CData + "|" + Timestamp`，防止 CData 单独被重放。

### 校验结果三态

| 结果 | 触发条件 | 处理方式 |
|---|---|---|
| `ResultOK` | 本地全部校验通过且新鲜 | 直接放行，按需异步预刷新 |
| `ResultNeedRemote` | 仅新鲜度过期，或本地无文件 | 联网校验，失败则拒绝启动 |
| `ResultInvalid` | 签名/机器码/过期/吊销明确不匹配 | 直接拒绝启动，保留旧文件 |

## 安装

```bash
go get github.com/doc-war/license-next
```

## 快速开始

### 1. 生成密钥对

```bash
openssl ecparam -genkey -name prime256v1 -out key-private.pem
openssl ec -in key-private.pem -pubout -out key-public.pem
```

### 2. 生成 CData（License 编码字符串）

打开 `official/issuer.html`（浏览器），输入 License 参数和 MasterKey，点击生成。

或者用 CLI：

```go
package main

import "github.com/doc-war/license-next/issuer"

iss, _ := issuer.New(issuer.Config{
    PrivateKey: privPEM,
    MasterKey:  masterKey,
})
ls, _ := iss.Sign(&issuer.License{
    Customer:         "acme-001",
    CustomerNickname: "Acme Corp",
    CustomerEmail:    "admin@acme.com",
    ExpireAt:         time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
    Product:          "myapp",
    MachineID:        "target-machine-id",
    Features:         []string{"premium", "audit-log"},
})
// ls.CData 就是 License 编码字符串
```

### 3. 部署 Cloudflare Worker

将 `worker/` 目录部署到 Cloudflare Workers：

```bash
cd worker
wrangler deploy
```

- 将 CData 存入 KV，key 为对应的 `machine_id`
- 私钥通过 `wrangler secret put PRIVATE_KEY` 设置

### 4. 客户端集成

```go
import licensenext "github.com/doc-war/license-next"

checker, err := licensenext.New(licensenext.Config{
    Product:   "myapp",
    PublicKey: pubPEM,
    MasterKey: masterKey,
    RemoteURL: "https://your-worker.workers.dev/v1/query",
})
if err != nil {
    log.Fatal(err)
}

lic, err := checker.Check(context.Background())
if err != nil {
    log.Fatalf("license校验失败: %v", err)
}

log.Printf("欢迎 %s，有效期至 %s", lic.CustomerNickname, lic.ExpireAt.Format("2006-01-02"))
log.Printf("可用功能: %v", lic.Features)
```

## Config

| 字段 | 默认值 | 说明 |
|---|---|---|
| `Product string` | 必填 | 产品名，用于隔离本地存储目录 |
| `PublicKey string` | 必填 | ECC 公钥 PEM |
| `RemoteURL string` | `""` | license 查询 API 地址 |
| `MasterKey string` | 必填 | CKD 主密钥 |
| `StorageDir string` | `~/.license-next/{product}/` | 本地存储根目录 |
| `FreshWindow time.Duration` | 7 天 | 新鲜度窗口 |
| `RefreshInterval time.Duration` | 3 天 | 异步预刷新节流间隔 |
| `HTTPTimeout time.Duration` | 5s | 远端请求超时（失败后自动重试一次） |

## 本地存储规范

```
~/.license-next/{product}/
  license.lic   # LicenseSign 的 base64url(JSON) 编码
  .state        # {"last_refresh_at": unix}
```

## 吊销说明

服务端在 `LicenseSign` 中设 `revoked: true`，客户端下次联网校验时读到即可拒绝。旧版本客户端忽略此字段，协议向前兼容。

## 子项目

| 目录 | 说明 |
|---|---|
| `official/` | 官网在线工具，`issuer.html` 生成 CData，`index.html` 文档页 |
| `wasm/` | 浏览器 WASM 入口（`GOOS=js` 编译），暴露 `encodeCData` |
| `worker/` | Cloudflare Worker 模板，Web Crypto 签名 + KV 查询 |
| `issuer/` | Go 服务端签发包（ECDSA 签名 + CKD 派生） |
| `cmd/wasm-issuer/` | wasip1 目标 WASM 编译（用于 Worker 内嵌签名） |
| `examples/` | 集成示例（checker / issuer / 全流程） |

## 验证方式

签名流程：

```
CData + "|" + Timestamp
  → SHA256
  → ECDSA P-256 签名（ASN.1 DER）
  → base64 StdEncoding
  → Signature 字段
```

客户端用公钥验证签名，确保 CData 和 Timestamp 未被篡改。Worker 侧使用 Web Crypto API 签名，与 Go 的 `crypto/ecdsa` 完全兼容。

## 服务端职责

- ECC 私钥安全保管（Worker 环境变量）
- 提供 `GET /v1/query?machine_id=xxx` 接口，返回 `LicenseSign` JSON
- 建议对该 API 做 IP 级限流

## 许可

MIT