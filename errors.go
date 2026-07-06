// Package licensenext 的错误定义。
// 所有 sentinel 错误均从 internal/core 透传，外部调用方可直接判断。
package licensenext

import "github.com/doc-war/license-next/internal/core"

var (
	ErrBadSignature    = core.ErrBadSignature    // 签名验证失败
	ErrMachineID       = core.ErrMachineID       // 机器码不匹配
	ErrExpired         = core.ErrExpired         // License 已过期
	ErrProductMismatch = core.ErrProductMismatch // 产品名不匹配
)
