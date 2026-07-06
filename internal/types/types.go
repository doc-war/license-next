// Package types 定义 license-next 的核心数据结构和常量。
// 被 internal/core 和 issuer 同时引用，对外通过 licensenext 包透出别名。
package types

import "time"

// License 授权合同明文，由服务端签发时序列化到 CData 中
type License struct {
	Customer         string    `json:"customer"`                    // 客户标识（机器码匹配依据）
	CustomerNickname string    `json:"customer_nickname,omitempty"` // 客户昵称（仅前台反显）
	CustomerEmail    string    `json:"customer_email,omitempty"`    // 客户邮箱（仅前台反显）
	ExpireAt         time.Time `json:"expire_at"`                    // 过期时间
	Product          string    `json:"product"`                      // 产品名
	Features         []string  `json:"features,omitempty"`           // 功能列表（可选）
	MachineID        string    `json:"machine_id"`                   // 绑定的机器码
}

// LicenseSign 服务端返回的完整签名结构
type LicenseSign struct {
	CData     string `json:"c_data"`               // License 编码数据（base64url 或 CKD 派生值）
	Timestamp int64  `json:"timestamp"`            // 签发时间戳（Unix 秒）
	Signature string `json:"signature"`            // ECDSA P-256 签名（ASN.1 DER, base64 StdEncoding）
	Revoked   bool   `json:"revoked,omitempty"`    // 吊销标记（omitempty 保证旧版客户端兼容）
}

// State 本地缓存状态，记录上次异步刷新时间
type State struct {
	LastRefreshAt int64 `json:"last_refresh_at"`    // 上次成功刷新时间（Unix 秒）
}

// CheckResult 本地校验结果三态枚举
type CheckResult int

const (
	ResultOK         CheckResult = iota // 本地缓存有效，直接通过
	ResultNeedRemote                    // 本地缓存过期或不存在，需要联网刷新
	ResultInvalid                       // 校验失败（签名/有效期/机器码等不通过）
)
