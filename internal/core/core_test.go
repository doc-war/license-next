// Package core 单元测试
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/doc-war/ckd"
	"github.com/doc-war/license-next/internal/types"
)

// generateTestKey 生成临时的 ECDSA P-256 密钥对供测试使用
func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &priv.PublicKey
}

// publicKeyToPEM 将公钥序列化为 PEM 格式字符串
func publicKeyToPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signLicense 用私钥对 (cdata, timestamp) 组合签名，返回 base64 StdEncoding
func signLicense(priv *ecdsa.PrivateKey, cdata string, timestamp int64) (string, error) {
	payload := fmt.Sprintf("%s|%d", cdata, timestamp)
	hash := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}
	sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// createLicenseSign 构造一个完整的 LicenseSign 用于测试
func createLicenseSign(t *testing.T, priv *ecdsa.PrivateKey, lic *types.License, timestamp int64) *types.LicenseSign {
	t.Helper()
	raw, err := json.Marshal(lic)
	if err != nil {
		t.Fatal(err)
	}
	cdata := B64Encode(raw)
	sig, err := signLicense(priv, cdata, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return &types.LicenseSign{CData: cdata, Timestamp: timestamp, Signature: sig}
}

// 测试公钥解析：正常 PEM 输入应返回正确的 ECDSA 公钥
func TestParsePublicKey(t *testing.T) {
	_, pub := generateTestKey(t)
	pemStr := publicKeyToPEM(t, pub)

	parsed, err := ParsePublicKey(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equal(pub) {
		t.Error("parsed public key does not match original")
	}
}

// 测试公钥解析：无效输入应报错
func TestParsePublicKey_Invalid(t *testing.T) {
	tests := []struct {
		name string
		pem  string
	}{
		{"empty", ""},
		{"invalid", "not a pem"},
		{"wrong type", "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.pem)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// 测试签名验证：正常的签名应验证通过
func TestVerifySignature_Valid(t *testing.T) {
	priv, pub := generateTestKey(t)
	lic := &types.License{
		Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Product: "test-product", Features: []string{"feature-a"}, MachineID: "test-machine",
	}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	if err := VerifySignature(pub, ls); err != nil {
		t.Fatal(err)
	}
}

// 测试签名验证：篡改 CData 后应拒绝
func TestVerifySignature_TamperedCData(t *testing.T) {
	priv, pub := generateTestKey(t)
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())
	ls.CData = B64Encode([]byte("{\"customer\":\"evil\"}"))

	if err := VerifySignature(pub, ls); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// 测试签名验证：篡改 Timestamp 后应拒绝
func TestVerifySignature_TamperedTimestamp(t *testing.T) {
	priv, pub := generateTestKey(t)
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())
	ls.Timestamp = 0

	if err := VerifySignature(pub, ls); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// 测试签名验证：篡改 Signature 后应拒绝
func TestVerifySignature_TamperedSignature(t *testing.T) {
	priv, pub := generateTestKey(t)
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())
	ls.Signature = base64.StdEncoding.EncodeToString([]byte("invalid-signature"))

	if err := VerifySignature(pub, ls); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// 测试签名验证：使用错误的公钥应拒绝
func TestVerifySignature_WrongKey(t *testing.T) {
	priv, _ := generateTestKey(t)
	_, wrongPub := generateTestKey(t)
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	if err := VerifySignature(wrongPub, ls); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// 测试 CData 解码：正常 CKD 输入应还原 License
func TestDecodeLicense(t *testing.T) {
	masterKey := "01234567890123456789012345678901"
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	raw, _ := json.Marshal(lic)
	cdata := mustDerive(t, raw, masterKey)

	decoded, err := DecodeLicense(cdata, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Customer != "test" || decoded.Product != "test-product" || decoded.MachineID != "test-machine" {
		t.Error("decoded fields do not match")
	}
	if !decoded.ExpireAt.Equal(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("unexpected ExpireAt: %v", decoded.ExpireAt)
	}
}

func mustDerive(t *testing.T, raw []byte, masterKey string) string {
	t.Helper()
	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{1: []byte(masterKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cdata, err := c.Derive(raw, "license")
	if err != nil {
		t.Fatal(err)
	}
	return cdata
}

// 测试 CData 解码：无效字符串应报错
func TestDecodeLicense_InvalidCData(t *testing.T) {
	masterKey := "01234567890123456789012345678901"
	_, err := DecodeLicense("!!!invalid-cdata!!!", masterKey)
	if err == nil {
		t.Error("expected error for invalid cdata")
	}
}

// 测试 CData 解码：无效 JSON 应报错
func TestDecodeLicense_InvalidJSON(t *testing.T) {
	masterKey := "01234567890123456789012345678901"
	cdata := mustDerive(t, []byte("{invalid json}"), masterKey)
	_, err := DecodeLicense(cdata, masterKey)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// 测试 CData 解码：CKD 完整往返（Derive → Parse）
func TestDecodeLicense_CKDRoundTrip(t *testing.T) {
	masterKey := string([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f})

	lic := &types.License{Customer: "ckd-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "ckd-product", MachineID: "ckd-machine"}
	raw, _ := json.Marshal(lic)

	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{1: []byte(masterKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cdata, err := c.Derive(raw, "license")
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeLicense(cdata, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Customer != "ckd-test" || decoded.Product != "ckd-product" {
		t.Error("CKD round trip decode failed")
	}
}

// 测试 CData 解码：CKD purpose 不匹配应报错
func TestDecodeLicense_CKDWrongPurpose(t *testing.T) {
	masterKey := "test-master-key-32bytes-long!!!"
	lic := &types.License{Customer: "test"}
	raw, _ := json.Marshal(lic)

	c, _ := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{1: []byte(masterKey)},
	})
	cdata, _ := c.Derive(raw, "api")

	_, err := DecodeLicense(cdata, masterKey)
	if err == nil {
		t.Error("expected error when purpose does not match")
	}
}

// 测试 CData 解码：CKD MasterKey 不匹配应报错
func TestDecodeLicense_CKDWrongKey(t *testing.T) {
	lic := &types.License{Customer: "test"}
	raw, _ := json.Marshal(lic)

	c, _ := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{1: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
	})
	cdata, _ := c.Derive(raw, "license")

	_, err := DecodeLicense(cdata, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err == nil {
		t.Error("expected error when MasterKey does not match")
	}
}

// 测试机器码校验
func TestCheckMachineID(t *testing.T) {
	lic := &types.License{MachineID: "abc"}
	if err := CheckMachineID(lic, "abc"); err != nil {
		t.Error("expected no error for matching machine ID")
	}
	if err := CheckMachineID(lic, "xyz"); err != ErrMachineID {
		t.Errorf("expected ErrMachineID, got %v", err)
	}
}

// 测试过期校验
func TestCheckExpire(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		expire time.Time
		want   error
	}{
		{"not expired", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), nil},
		{"expired", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), ErrExpired},
		{"expired today", time.Date(2025, 5, 31, 0, 0, 0, 0, time.UTC), ErrExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lic := &types.License{ExpireAt: tt.expire}
			if err := CheckExpire(lic, now); err != tt.want {
				t.Errorf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

// 测试产品名校验
func TestCheckProduct(t *testing.T) {
	lic := &types.License{Product: "myapp"}
	if err := CheckProduct(lic, "myapp"); err != nil {
		t.Error("expected no error for matching product")
	}
	if err := CheckProduct(lic, "otherapp"); err != ErrProductMismatch {
		t.Errorf("expected ErrProductMismatch, got %v", err)
	}
}

// 测试签名新鲜度检查
func TestCheckFreshness(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	window := 7 * 24 * time.Hour

	tests := []struct {
		name     string
		signedAt time.Time
		expectOK bool
	}{
		{"within window", now.Add(-1 * 24 * time.Hour), true},
		{"exactly at window", now.Add(-7 * 24 * time.Hour), true},
		{"just over window", now.Add(-8 * 24 * time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &types.LicenseSign{Timestamp: tt.signedAt.Unix()}
			got := CheckFreshness(ls, window, now)
			if got != tt.expectOK {
				t.Errorf("expected %v, got %v", tt.expectOK, got)
			}
		})
	}
}

// 测试 Base64 编解码往返
func TestB64RoundTrip(t *testing.T) {
	input := []byte("hello license-next")
	encoded := B64Encode(input)
	decoded, err := B64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(input) {
		t.Errorf("round trip failed: %s != %s", decoded, input)
	}
}

// 测试无效 Base64 解码应报错
func TestB64Decode_Invalid(t *testing.T) {
	_, err := B64Decode("!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// 测试 License 存储：保存后加载应一致
func TestStore_SaveAndLoadLicense(t *testing.T) {
	dir := t.TempDir()
	priv, _ := generateTestKey(t)
	lic := &types.License{Customer: "store-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "store-product", MachineID: "store-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	if err := SaveLicense(dir, ls); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadLicense(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CData != ls.CData || loaded.Timestamp != ls.Timestamp || loaded.Signature != ls.Signature {
		t.Error("license fields mismatch after save/load")
	}
}

// 测试 License 加载：文件不存在应报错
func TestStore_LoadLicense_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadLicense(dir)
	if err == nil {
		t.Error("expected error for missing license file")
	}
}

// 测试 State 存储：保存后加载应一致，缺失文件返回空 State
func TestStore_State(t *testing.T) {
	dir := t.TempDir()

	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastRefreshAt != 0 {
		t.Error("expected zero-value state for missing file")
	}

	st.LastRefreshAt = 12345
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastRefreshAt != 12345 {
		t.Errorf("expected LastRefreshAt=12345, got %d", loaded.LastRefreshAt)
	}
}

// 测试 State 加载：损坏的文件返回空 State（不报错）
func TestStore_State_Corrupted(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, stateFileName), []byte("{invalid"), 0600)

	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastRefreshAt != 0 {
		t.Error("expected zero-value state for corrupted file")
	}
}

// 测试远程拉取：正常返回应正确解析 LicenseSign
func TestRemote_Fetch(t *testing.T) {
	priv, _ := generateTestKey(t)
	lic := &types.License{Customer: "remote-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "remote-product", MachineID: "remote-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("machine_id") != "remote-machine" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ls)
	}))
	defer server.Close()

	fetched, err := FetchLicense(context.Background(), server.URL, "remote-machine", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.CData != ls.CData {
		t.Error("CData mismatch from remote fetch")
	}
}

// 测试远程拉取：非 200 状态码应报错
func TestRemote_Fetch_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchLicense(context.Background(), server.URL, "test", time.Second)
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}

// 测试远程拉取：context 超时应报错
func TestRemote_Fetch_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := FetchLicense(ctx, server.URL, "test", time.Second)
	if err == nil {
		t.Error("expected error for context timeout")
	}
}

// 测试远程拉取：无效 JSON 响应应报错
func TestRemote_Fetch_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	_, err := FetchLicense(context.Background(), server.URL, "test", time.Second)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// 测试 CData 解码：空字符串应报错
func TestDecodeLicense_EmptyCData(t *testing.T) {
	_, err := DecodeLicense("", "01234567890123456789012345678901")
	if err == nil {
		t.Error("expected error for empty cdata")
	}
}

// 测试新鲜度检查：零窗口和负窗口的处理
func TestCheckFreshness_ZeroWindow(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		signedAt time.Time
		window   time.Duration
		expectOK bool
	}{
		{"zero window, past", now.Add(-1 * time.Second), 0, false},
		{"negative window", now.Add(-1 * time.Second), -1 * time.Hour, false},
		{"zero window, future signed", now.Add(1 * time.Hour), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &types.LicenseSign{Timestamp: tt.signedAt.Unix()}
			got := CheckFreshness(ls, tt.window, now)
			if got != tt.expectOK {
				t.Errorf("expected %v, got %v", tt.expectOK, got)
			}
		})
	}
}

// 测试 P-256 签名的 R, S 值不超过 256 位
func TestLargeIntegersInSignature(t *testing.T) {
	priv, pub := generateTestKey(t)
	lic := &types.License{Customer: "test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "test-product", MachineID: "test-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	sigRaw, _ := base64.StdEncoding.DecodeString(ls.Signature)
	var sig ecdsaSignature
	asn1.Unmarshal(sigRaw, &sig)

	if sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		t.Error("R or S values exceed expected size for P-256")
	}

	if err := VerifySignature(pub, ls); err != nil {
		t.Fatal(err)
	}
}

// 测试签名验证：损坏的签名字节应拒绝
func TestVerifySignature_CorruptedSignatureBytes(t *testing.T) {
	_, pub := generateTestKey(t)
	ls := &types.LicenseSign{
		CData: B64Encode([]byte("{\"customer\":\"test\"}")), Timestamp: 1000,
		Signature: base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5}),
	}
	if err := VerifySignature(pub, ls); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// 测试 Base64 编解码：大数据往返
func TestB64RoundTrip_LargeData(t *testing.T) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	encoded := B64Encode(data)
	decoded, err := B64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range decoded {
		if b != data[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
	}
}

// 测试 License 存储：验证磁盘文件内容正确
func TestStore_SaveLicense_VerifyOnDisk(t *testing.T) {
	dir := t.TempDir()
	priv, _ := generateTestKey(t)
	now := time.Now()

	lic := &types.License{Customer: "disk-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "disk-product", MachineID: "disk-machine"}
	ls := createLicenseSign(t, priv, lic, now.Unix())

	if err := SaveLicense(dir, ls); err != nil {
		t.Fatal(err)
	}

raw, err := os.ReadFile(filepath.Join(dir, "license.lic"))
	if err != nil {
		t.Fatal(err)
	}

	var stored types.LicenseSign
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.CData != ls.CData {
		t.Error("license file content mismatch")
	}
}

// 测试 License 存储：SaveLicense 会在目录不存在时自动创建
func TestStore_SaveLicense_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	priv, _ := generateTestKey(t)
	lic := &types.License{Customer: "mkdir-test", ExpireAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Product: "mkdir-product", MachineID: "mkdir-machine"}
	ls := createLicenseSign(t, priv, lic, time.Now().Unix())

	if err := SaveLicense(dir, ls); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("directory should have been created")
	}
}

// 测试获取机器码
func TestGetMachineID(t *testing.T) {
	mid, err := GetMachineID("test-app")
	if err != nil {
		t.Skipf("machineid not available: %v", err)
	}
	if mid == "" {
		t.Error("expected non-empty machine ID")
	}
}

// 测试远程拉取：验证 machine_id 查询参数正确传递
func TestRemote_Fetch_SetsQueryParam(t *testing.T) {
	var seenMachineID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMachineID = r.URL.Query().Get("machine_id")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&types.LicenseSign{})
	}))
	defer server.Close()

	FetchLicense(context.Background(), server.URL, "my-machine", time.Second)
	if seenMachineID != "my-machine" {
		t.Errorf("expected machine_id=my-machine, got %s", seenMachineID)
	}
}
