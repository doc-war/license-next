// Package core 的校验函数：
// 产品名、机器码、过期时间、签名新鲜度检查。
package core

import (
	"time"

	"github.com/doc-war/license-next/internal/types"
)

// CheckMachineID 校验 License 绑定的机器码是否与本地一致
func CheckMachineID(lic *types.License, localMID string) error {
	if lic.MachineID != localMID {
		return ErrMachineID
	}
	return nil
}

// CheckExpire 校验 License 是否已超过过期时间
func CheckExpire(lic *types.License, now time.Time) error {
	if now.After(lic.ExpireAt) {
		return ErrExpired
	}
	return nil
}

// CheckProduct 校验 License 产品名是否与当前应用匹配
func CheckProduct(lic *types.License, product string) error {
	if lic.Product != product {
		return ErrProductMismatch
	}
	return nil
}

// CheckFreshness 校验签名时间戳是否在新鲜窗口内。
// 返回 true 表示无需联网刷新。
func CheckFreshness(ls *types.LicenseSign, window time.Duration, now time.Time) bool {
	signedAt := time.Unix(ls.Timestamp, 0)
	return now.Sub(signedAt) <= window
}
