package idp

// Reason 是对认证/鉴权失败原因的稳定分类。
type Reason string

const (
	ReasonUnknownKey      Reason = "unknown_key"     // 令牌头部声明的密钥版本不存在或已被清除
	ReasonKeyNotActive    Reason = "key_not_active"  // 密钥版本存在，但既不在签发期也不在验证宽限期
	ReasonTokenExpired    Reason = "token_expired"   // 令牌已过 exp
	ReasonBadSignature    Reason = "bad_signature"   // 签名与重算结果不匹配
	ReasonMalformedToken  Reason = "malformed_token" // 令牌无法解析
	ReasonInvalidGrant    Reason = "invalid_grant"   // 刷新凭据未知、已轮换或已被重放
	ReasonSessionRevoked  Reason = "session_revoked" // 会话链路已被终止
	ReasonUnauthenticated Reason = "unauthenticated" // 请求缺少/携带无效凭据
	ReasonForbidden       Reason = "forbidden"       // 已认证但角色或作用域不足
)

// Error 携带稳定的原因码与可解释的人类可读细节。
type Error struct {
	Reason  Reason
	Message string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }

func NewError(r Reason, msg string) *Error { return &Error{Reason: r, Message: msg} }
