// Package authz 实现基于角色与作用域的鉴权判定。
//
// 判定结论只有三种，且“未认证”与“权限不足”严格区分：
//
//	DecisionDenyUnauthenticated 令牌缺失、无法解析、密钥未知/失效、
//	                             签名错误或已过期 —— 调用方身份不可信。
//	DecisionDenyForbidden        令牌有效、身份可信，但角色或作用域不满足策略。
//	DecisionAllow                身份可信且策略满足。
//
// 策略语义：
//   - NeedAnyRole 为空表示“不要求特定角色”（任何已认证身份即可）；
//     非空时令牌角色集合与之有交集即满足。
//   - NeedScopes  要求令牌作用域包含全部所需作用域（AND 语义）。
package authz

import (
	"context"
	"sort"
	"strings"

	idp "github.com/h3yow/identity-provider-go/internal"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

// Decision 是鉴权结论。
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDenyUnauthenticated
	DecisionDenyForbidden
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDenyUnauthenticated:
		return "deny_unauthenticated"
	default:
		return "deny_forbidden"
	}
}

// Outcome 携带判定结论与依据，便于输出可解释日志。
type Outcome struct {
	Decision Decision
	Envelope *tokens.Envelope
	// Reason 在拒绝时给出稳定原因码（与 idp.Reason 对齐）或权限说明。
	Reason string
	// Detail 是人类可读的判定依据。
	Detail string
	// MissingRoles/MissingScopes 在 forbidden 时列出缺口。
	MissingRoles  []string
	MissingScopes []string
}

// Policy 描述访问某资源所需的角色（任一满足）与作用域（全部满足）。
type Policy struct {
	NeedAnyRole []string
	NeedScopes  []string
}

// Authorizer 组合令牌验证与策略判定；判定是纯函数式的、无内部可变状态，
// 因此并发请求下对同一输入必然得到同一结论。
type Authorizer struct {
	verifier *tokens.Verifier
}

// NewAuthorizer 创建鉴权器。
func NewAuthorizer(v *tokens.Verifier) *Authorizer { return &Authorizer{verifier: v} }

// Authorize 解析并验证令牌，再对照策略做判定。
func (a *Authorizer) Authorize(ctx context.Context, rawToken string, p Policy) Outcome {
	if strings.TrimSpace(rawToken) == "" {
		return Outcome{
			Decision: DecisionDenyUnauthenticated,
			Reason:   string(idp.ReasonUnauthenticated),
			Detail:   "missing bearer token",
		}
	}
	env, err := a.verifier.Verify(rawToken)
	if err != nil {
		// 所有令牌层面的失败都归类为“未认证”，并保留可区分的原因码。
		reason := string(idp.ReasonUnauthenticated)
		detail := err.Error()
		var ie *idp.Error
		if asError(err, &ie) {
			reason = string(ie.Reason)
		}
		return Outcome{
			Decision: DecisionDenyUnauthenticated,
			Reason:   reason,
			Detail:   detail,
		}
	}

	if missingRoles, missingScopes, ok := evaluate(env.Claims, p); !ok {
		return Outcome{
			Decision:      DecisionDenyForbidden,
			Envelope:      env,
			Reason:        string(idp.ReasonForbidden),
			Detail:        explainForbidden(env.Claims, p, missingRoles, missingScopes),
			MissingRoles:  missingRoles,
			MissingScopes: missingScopes,
		}
	}

	return Outcome{
		Decision: DecisionAllow,
		Envelope: env,
		Detail:   "roles/scopes satisfy policy",
	}
}

func asError(err error, target **idp.Error) bool {
	for err != nil {
		if e, ok := err.(*idp.Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// evaluate 返回未命中的角色（仅当策略要求角色却无交集时给出全部要求角色）
// 与缺失的作用域；ok 为 true 表示满足策略。
func evaluate(c tokens.Claims, p Policy) (missingRoles, missingScopes []string, ok bool) {
	roleSet := toSet(c.Roles)
	if len(p.NeedAnyRole) > 0 {
		hit := false
		for _, r := range p.NeedAnyRole {
			if roleSet[r] {
				hit = true
				break
			}
		}
		if !hit {
			missingRoles = append([]string(nil), p.NeedAnyRole...)
			sort.Strings(missingRoles)
		}
	}
	scopeSet := toSet(c.Scopes)
	for _, s := range p.NeedScopes {
		if !scopeSet[s] {
			missingScopes = append(missingScopes, s)
		}
	}
	sort.Strings(missingScopes)
	return missingRoles, missingScopes, len(missingRoles) == 0 && len(missingScopes) == 0
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func explainForbidden(c tokens.Claims, p Policy, missingRoles, missingScopes []string) string {
	var b strings.Builder
	b.WriteString("subject=")
	b.WriteString(c.Subject)
	if len(missingRoles) > 0 {
		b.WriteString(" lacks any required role ")
		b.WriteString(strings.Join(missingRoles, "|"))
		b.WriteString(" (have: ")
		b.WriteString(orNone(c.Roles))
		b.WriteString(")")
	}
	if len(missingScopes) > 0 {
		if len(missingRoles) > 0 {
			b.WriteString("; ")
		}
		b.WriteString(" missing scopes ")
		b.WriteString(strings.Join(missingScopes, ","))
		b.WriteString(" (have: ")
		b.WriteString(orNone(c.Scopes))
		b.WriteString(")")
	}
	return b.String()
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}
