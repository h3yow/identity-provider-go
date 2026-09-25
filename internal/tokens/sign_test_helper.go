package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
)

// signRaw 用给定密钥重算签名，供测试构造篡改令牌。
func signRaw(signingInput string, secret []byte, parts []string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	parts[3] = b64.EncodeToString(mac.Sum(nil))
	out := "v1"
	for _, p := range parts[1:] {
		out += "." + p
	}
	return out
}
