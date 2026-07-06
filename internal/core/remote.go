// Package core 的远程拉取函数：
// 向远端服务查询 License 并返回 LicenseSign。
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/doc-war/license-next/internal/types"
)

// FetchLicense 向远端 URL 发起 GET 请求，携带 machine_id 参数，
// 返回解析后的 LicenseSign。响应体限制最大 1MB。
// 失败时自动重试一次，间隔 1 秒，适合 Pages / Worker 等按需启动的场景。
func FetchLicense(ctx context.Context, url, machineID string, timeout time.Duration) (*types.LicenseSign, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
		ls, err := fetchOnce(ctx, url, machineID, timeout)
		if err == nil {
			return ls, nil
		}
		if attempt == 0 {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("licensenext: 远端请求失败（重试后）")
}

func fetchOnce(ctx context.Context, url, machineID string, timeout time.Duration) (*types.LicenseSign, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("machine_id", machineID)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("licensenext: 远端请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("licensenext: 远端返回异常状态码 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("licensenext: 远端响应读取失败: %w", err)
	}

	var ls types.LicenseSign
	if err := json.Unmarshal(body, &ls); err != nil {
		return nil, fmt.Errorf("licensenext: 远端响应解析失败: %w", err)
	}
	return &ls, nil
}
