# identity-provider-go

一套**本地可运行**的身份认证与令牌服务。无外部依赖（仅 Go 标准库），
密钥与令牌的完整生命周期全部由**进程内状态**模拟，签发、刷新与鉴权在
HTTP 与直接调用两个入口下给出一致且可解释的结论。

- 语言：Go 1.25，模块 `github.com/h3yow/identity-provider-go`
- 令牌：紧凑格式 `v1.<kid>.<payload>.<sig>`，HMAC-SHA256，显式携带密钥版本
- 状态：密钥环、会话/刷新凭据均在内存中，带互斥锁，并发安全

## 目录结构

```
internal/
  errors.go           稳定错误原因码（Reason）与可解释错误类型
  keys/               多版本签名密钥环：轮换 / 过渡 / 退役
  tokens/             令牌签发与验证（签名、过期、原因分类）
  sessions/           会话与一次性刷新凭据：轮换 / 重放识别 / 吊销
  authz/              基于角色与作用域的鉴权
  service/            组装以上组件 + HTTP 入口
cmd/server/main.go    本地 HTTP 服务（:8080）
```

## 1. 签名密钥轮换策略

每个密钥版本**不可变**（轮换 = 引入新版本，绝不修改旧密钥）。版本有三种状态：

| 状态 | 可签发 | 可验证 | 说明 |
|---|---|---|---|
| `active` | 是 | 是 | 全环同时只有一个 active，新令牌一律用它签发 |
| `verifying` | 否 | 是 | **过渡期**。轮换时旧 active 自动进入此状态 |
| `retired` | 否 | 否 | 过渡期结束后显式退役，令牌立即被拒 |

确定的过渡语义：

1. `RotateKey()` 后，新令牌由新版本签发；旧版本签发的**未过期令牌仍然通过验证**，
   因此“多个处于有效期的密钥共存”时它们签发的令牌都有效，轮换不需要踢人下线。
2. 过渡期长度由运维控制：确认旧令牌都已过期（或已刷新）后调用
   `RetireKey(oldVersion)` 关闭窗口。`active` 密钥不能直接退役（必须先轮换）。
3. 验证失败时三类结论严格区分，排查时一眼可辨：
   - `unknown_key`：令牌头部的 `kid` **从未登记**（伪造或来自其他系统）
   - `key_not_active`：`kid` 存在但已 `retired`（过渡窗口已结束）
   - `bad_signature`：`kid` 有效（active/verifying）但 HMAC 不匹配（内容被篡改）

## 2. 刷新凭据与重放规则

每个会话是一条**只进不退的凭据链** `cred#1 → cred#2 → …`，凭据为 256 位随机不透明 ID：

- **一次性轮换**：刷新成功即原子地把当前凭据作废、发放下一版本；
  访问令牌内嵌 `session_id` 与 `cred_version`，刷新不产生新会话。
- **并发安全**：同一凭据并发刷新时，所有调用在同一把锁下串行判定，
  **恰有一个成功**，失败方不会产生重复会话或状态分叉。
- **重放识别与链路终止**：任何已使用（或非当前）凭据再次出现即判定为重放，
  会话立即标记 `revoked`；**此后连当前凭据也无法刷新**（会话链路整体终止，
  防止攻击者利用窗口继续换票）。
- **与其它异常区分**：
  - 凭据 ID 从未发放 → `invalid_grant`（HTTP 401）
  - 凭据已过期 → `invalid_grant`，但**不吊销会话**（过期不是攻击信号）
  - 旧凭据重放 / 会话已吊销 → `session_revoked`（HTTP 403）

刷新得到的访问令牌，其角色与作用域始终取自会话创建时保存的
**授权快照**，刷新永远不会扩大权限。

## 3. 鉴权模型（角色 + 作用域）

策略 `Policy{NeedAnyRole, NeedScopes}` 的语义：

- `NeedAnyRole`：非空时令牌角色与之**有交集**即满足（OR）；为空表示不要求角色。
- `NeedScopes`：令牌作用域必须**包含全部**所需作用域（AND）。

结论只有三种，**「未认证」与「权限不足」严格区分**：

| 结论 | HTTP | 含义 |
|---|---|---|
| `allow` | 200 | 身份可信且策略满足 |
| `deny_unauthenticated` | 401 | 无令牌、格式错、密钥未知/退役、签名错、已过期——身份不可信 |
| `deny_forbidden` | 403 | 令牌有效、身份可信，但角色/作用域不足；响应给出缺失项 |

401 响应保留底层细分原因码（`malformed_token` / `unknown_key` /
`key_not_active` / `bad_signature` / `token_expired`），因此“拒绝”既分类统一、
原因又可区分。鉴权是无内部可变状态的纯判定，并发下同一输入结论稳定。

## 4. HTTP 接口

| 方法/路径 | 作用 |
|---|---|
| `POST /login` | 入参 `subject, roles, scopes`；返回访问令牌、刷新令牌、密钥版本、会话 ID |
| `POST /refresh` | 入参 `refresh_token`；一次性轮换，返回新的双令牌 |
| `POST /authorize` | 入参 `access_token, need_any_role, need_scopes`；也支持 `Authorization: Bearer` |
| `POST /introspect` | 令牌体检：`active` 与全部声明，失败给原因码 |
| `POST /admin/keys/rotate` | 轮换签名密钥，返回各版本状态 |
| `GET /healthz` | 存活检查 |

### 本地运行与 curl 验证

```bash
go run ./cmd/server          # 默认监听 :8080

# 登录
curl -s -X POST localhost:8080/login \
  -d '{"subject":"alice","roles":["admin"],"scopes":["read","write"]}'

# 鉴权（权限不足返回 403 forbidden；无/坏令牌返回 401）
curl -s -X POST localhost:8080/authorize \
  -d '{"access_token":"<AT>","need_any_role":["admin"],"need_scopes":["write"]}'

# 轮换密钥；轮换后立刻 introspect 旧令牌仍为 active（verifying 过渡期）
curl -s -X POST localhost:8080/admin/keys/rotate

# 刷新；用同一个旧 refresh_token 再调一次即得到 403 session_revoked
curl -s -X POST localhost:8080/refresh -d '{"refresh_token":"<RT>"}'
```

服务端日志会打印关键输入（凭据仅打印前后 4 位指纹）与判定依据，例如：

```
authorize input: token_fingerprint=v1....AsQ need_scopes=[delete]
authorize deny(forbidden): reason=forbidden basis="subject=alice missing scopes delete (have: read,write)"
refresh denied: fingerprint=WKHD...vV7I reason=session_revoked detail="refresh credential replay detected; session chain terminated"
```

## 5. 测试与本地验证

```bash
go test ./...                 # 全部单测
go test -race ./...           # 带竞态检测（并发刷新场景）
go test -v ./internal/service # 端到端用例的关键输入与判定依据日志
```

关键覆盖场景：

- `keys`：三版本轮换后的状态机、重复版本/直接退役 active 等守卫、
  20 路并发轮换后 active 唯一；过渡期验证与退役后拒绝、未知版本区分。
- `tokens`：正常签发验证；`expired / malformed / unknown_key /
  bad_signature` 分类；轮换后新旧两个 `kid` 的令牌同时通过，
  旧版本退役后变为 `key_not_active`。
- `sessions`：链推进、旧凭据重放吊销整条链、过期不吊销；
  **64 路并发同一刷新凭据恰有 1 个成功、只生成 1 个新凭据**。
- `authz`：allow / 403 / 401 三分，401 内细分原因可辨，角色 OR / 作用域 AND，
  100×3 路并发结论稳定。
- `service` / HTTP：端到端串联轮换、刷新重放、并发刷新、刷新不越权，
  以及 401 与 403 的状态码语义。

所有测试用例均通过标准 `log` 打印**关键输入与判定依据**，
可用 `go test -v` 查看完整判定链路。
