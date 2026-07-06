// Package core 的本地持久化函数：
// License 缓存和 State 状态的读写。
package core

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/doc-war/license-next/internal/types"
)

const (
	licenseFileName = "license.lic"  // LicenseSign 本地缓存文件名
	stateFileName   = ".state"       // 状态文件名（LastRefreshAt）
)

// LoadLicense 从本地目录读取缓存的 LicenseSign
func LoadLicense(dir string) (*types.LicenseSign, error) {
	raw, err := os.ReadFile(filepath.Join(dir, licenseFileName))
	if err != nil {
		return nil, err
	}
	data, err := B64Decode(string(raw))
	if err != nil {
		return nil, err
	}
	var ls types.LicenseSign
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

// SaveLicense 将 LicenseSign 写入本地缓存（先 JSON 序列化，再 Base64 编码）
func SaveLicense(dir string, ls *types.LicenseSign) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	encoded := B64Encode(raw)
	return os.WriteFile(filepath.Join(dir, licenseFileName), []byte(encoded), 0600)
}

// LoadState 从本地读取状态。若文件不存在或损坏，返回空 State（不报错）
func LoadState(dir string) (*types.State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		return &types.State{}, nil
	}
	var st types.State
	if err := json.Unmarshal(raw, &st); err != nil {
		return &types.State{}, nil
	}
	return &st, nil
}

// SaveState 将状态写入本地文件
func SaveState(dir string, st *types.State) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFileName), raw, 0600)
}
