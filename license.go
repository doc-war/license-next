// Package licensenext 是 license-next 的客户端入口包。
// 使用方只需 import "github.com/doc-war/license-next"，
// 通过 New(cfg) 创建 Checker，然后调用 Check() 完成校验。
package licensenext

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/doc-war/license-next/internal/core"
	"github.com/doc-war/license-next/internal/types"
)

// License 授权合同内容（类型别名，对内暴露 types.License）
type License = types.License

// LicenseSign 服务端返回的完整签名结构（类型别名）
type LicenseSign = types.LicenseSign

// CheckResult 校验结果三态（类型别名）
type CheckResult = types.CheckResult

const (
	// ResultOK 本地缓存验证通过，且签名新鲜度在 FreshWindow 内
	ResultOK = types.ResultOK
	// ResultNeedRemote 本地缓存验证通过但签名已过期，需要联网刷新
	ResultNeedRemote = types.ResultNeedRemote
	// ResultInvalid 校验失败（签名无效 / 过期 / 机器码不匹配等）
	ResultInvalid = types.ResultInvalid
)

// Checker 客户端校验器，持有公钥、机器码等运行时上下文
type Checker struct {
	product         string           // 产品名，用于 CheckProduct
	machineID       string           // 本地机器码，在 New 时自动获取
	pubKey          *ecdsa.PublicKey // 解析后的 ECC 公钥
	masterKey       string           // CKD MasterKey
	remoteURL       string           // 远端校验接口地址（可选）
	storeDir        string           // 本地缓存目录
	freshWindow     time.Duration    // 签名新鲜度窗口
	refreshInterval time.Duration    // 异步刷新间隔
	httpTimeout     time.Duration    // HTTP 请求超时
	now             func() time.Time // 可注入的时间函数（便于测试）
}

// Config 客户端配置，传给 New 创建 Checker
type Config struct {
	Product   string // 必填，产品名
	PublicKey string // 必填，PEM 格式的 ECC 公钥
	MasterKey string // 必填，CKD MasterKey
	RemoteURL string // 选填，远端 License 查询接口

	StorageDir      string        // 选填，缓存目录（默认 ~/.license-next/<product>）
	FreshWindow     time.Duration // 选填，签名新鲜度（默认 7 天）
	RefreshInterval time.Duration // 选填，异步刷新间隔（默认 3 天）
	HTTPTimeout     time.Duration // 选填，HTTP 超时（默认 5 秒）
}

// applyDefaults 填充 Config 中的零值字段，并校验必需字段
func applyDefaults(cfg *Config) error {
	if cfg.Product == "" {
		return errors.New("licensenext: Product 不能为空")
	}
	if cfg.PublicKey == "" {
		return errors.New("licensenext: PublicKey 不能为空")
	}
	if cfg.MasterKey == "" {
		return errors.New("licensenext: MasterKey 不能为空")
	}
	if cfg.StorageDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("licensenext: 获取用户目录失败: %w", err)
		}
		cfg.StorageDir = filepath.Join(home, ".license-next", cfg.Product)
	}
	if cfg.FreshWindow == 0 {
		cfg.FreshWindow = 7 * 24 * time.Hour
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 3 * 24 * time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	return nil
}

// New 创建 Checker 实例，自动获取机器码、解析公钥
func New(cfg Config) (*Checker, error) {
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}

	mid, err := core.GetMachineID("license-next")
	if err != nil {
		return nil, fmt.Errorf("licensenext: 获取机器码失败: %w", err)
	}

	pub, err := core.ParsePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("licensenext: 公钥解析失败: %w", err)
	}

	return &Checker{
		product:         cfg.Product,
		machineID:       mid,
		pubKey:          pub,
		masterKey:       cfg.MasterKey,
		remoteURL:       cfg.RemoteURL,
		storeDir:        cfg.StorageDir,
		freshWindow:     cfg.FreshWindow,
		refreshInterval: cfg.RefreshInterval,
		httpTimeout:     cfg.HTTPTimeout,
		now:             time.Now,
	}, nil
}

// Check 执行 License 校验。优先本地缓存，必要时联网刷新。
// 返回 License 指针和可公开的错误。
func (c *Checker) Check() (*License, error) {
	result, lic, err := c.checkLocal()

	switch result {
	case ResultOK:
		// 本地缓存通过，后台异步刷新
		c.maybeRefreshAsync()
		return lic, nil

	case ResultNeedRemote:
		// 需要联网刷新
		if c.remoteURL == "" {
			return nil, errors.New("licensenext: license需联网校验但未配置RemoteURL")
		}
		ls, ferr := core.FetchLicense(context.Background(), c.remoteURL, c.machineID, c.httpTimeout)
		if ferr != nil {
			return nil, fmt.Errorf("licensenext: license需联网校验但连接失败: %w", ferr)
		}
		return c.validateAndPersist(ls)

	default:
		if err != nil {
			return nil, err
		}
		return nil, errors.New("licensenext: license校验失败")
	}
}

// Verify 验证并持久化 LicenseSign JSON（.lic 文件内容）。
// 成功后将 License 缓存到本地，后续可直接调用 Check() 或 SimpleCheck()。
func (c *Checker) Verify(licJSON string) (*License, error) {
	var ls LicenseSign
	if err := json.Unmarshal([]byte(licJSON), &ls); err != nil {
		return nil, fmt.Errorf("licensenext: LicenseSign 解析失败: %w", err)
	}
	return c.validateAndPersist(&ls)
}

// SimpleCheck 执行完全的本地校验，不解码缓存、不联网、不检查新鲜度。
// 适用于不依赖远端刷新场景的离线校验。
func (c *Checker) SimpleCheck() (*License, error) {
	ls, err := core.LoadLicense(c.storeDir)
	if err != nil {
		return nil, fmt.Errorf("licensenext: 未找到本地license: %w", err)
	}
	if ls.Revoked {
		return nil, errors.New("licensenext: license已被吊销")
	}
	if err := core.VerifySignature(c.pubKey, ls); err != nil {
		return nil, err
	}
	lic, err := core.DecodeLicense(ls.CData, c.masterKey)
	if err != nil {
		return nil, err
	}
	if err := core.CheckProduct(lic, c.product); err != nil {
		return nil, err
	}
	if err := core.CheckMachineID(lic, c.machineID); err != nil {
		return nil, err
	}
	if err := core.CheckExpire(lic, c.now()); err != nil {
		return nil, err
	}
	return lic, nil
}

func (c *Checker) checkLocal() (CheckResult, *License, error) {
	ls, err := core.LoadLicense(c.storeDir)
	if err != nil {
		// 本地无缓存 → 需要联网
		return ResultNeedRemote, nil, nil
	}

	// 检查是否已被吊销
	if ls.Revoked {
		return ResultInvalid, nil, errors.New("licensenext: license已被吊销")
	}

	// 验证 ECDSA 签名
	if err := core.VerifySignature(c.pubKey, ls); err != nil {
		return ResultInvalid, nil, err
	}

	// 解码 CData 还原 License 明文
	lic, err := core.DecodeLicense(ls.CData, c.masterKey)
	if err != nil {
		return ResultInvalid, nil, err
	}

	// 逐项校验：产品名 / 机器码 / 有效期
	if err := core.CheckProduct(lic, c.product); err != nil {
		return ResultInvalid, nil, err
	}
	if err := core.CheckMachineID(lic, c.machineID); err != nil {
		return ResultInvalid, nil, err
	}
	if err := core.CheckExpire(lic, c.now()); err != nil {
		return ResultInvalid, nil, err
	}

	// 签名新鲜度检查
	if !core.CheckFreshness(ls, c.freshWindow, c.now()) {
		return ResultNeedRemote, lic, nil
	}
	return ResultOK, lic, nil
}

// validateAndPersist 校验远程返回的 LicenseSign 并缓存到本地
func (c *Checker) validateAndPersist(ls *LicenseSign) (*License, error) {
	if ls.Revoked {
		return nil, errors.New("licensenext: license已被吊销")
	}

	if err := core.VerifySignature(c.pubKey, ls); err != nil {
		return nil, err
	}
	lic, err := core.DecodeLicense(ls.CData, c.masterKey)
	if err != nil {
		return nil, err
	}
	if err := core.CheckProduct(lic, c.product); err != nil {
		return nil, err
	}
	if err := core.CheckMachineID(lic, c.machineID); err != nil {
		return nil, err
	}
	if err := core.CheckExpire(lic, c.now()); err != nil {
		return nil, err
	}

	// 持久化缓存
	_ = core.SaveLicense(c.storeDir, ls)
	_ = core.SaveState(c.storeDir, &types.State{LastRefreshAt: c.now().Unix()})
	return lic, nil
}

// maybeRefreshAsync 在满足刷新间隔时，异步从远端拉取最新 License 并缓存
func (c *Checker) maybeRefreshAsync() {
	if c.remoteURL == "" {
		return
	}
	st, _ := core.LoadState(c.storeDir)
	if c.now().Sub(time.Unix(st.LastRefreshAt, 0)) < c.refreshInterval {
		return
	}
	go func() {
		ls, err := core.FetchLicense(context.Background(), c.remoteURL, c.machineID, c.httpTimeout)
		if err != nil {
			return
		}
		_, _ = c.validateAndPersist(ls)
	}()
}
