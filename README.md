# identity-provider-go

一个**本地可运行**的身份认证与令牌服务。所有密钥版本、会话与刷新链路都保存在
进程内存中（重启即清空），用它来完整模拟「签发 → 鉴权 → 刷新 → 轮换/重放」的
生命周期，并在 Go API 与 HTTP 两种入口下给出一致、可解释的结论。

仅依赖 Go 标准库（`HMAC-SHA256` 签名，不使用外部 JWT 库），Go 版本见 `go.mod`。

## 目录结构

```
internal/keys    签名密钥多版本、三态生命周期与轮换
internal/tokens  紧凑签名令牌（签发/验签）与不透明刷新凭据，错误细分类
internal/auth    登录、一次性刷新轮换链、重放识别、认证入口
internal/authz   基于角色/作用域的四值鉴权
internal/server  HTTP 入口，错误码 -> HTTP 语义
cmd/idp          组装并启动服务（默认 :8080）
```

## 1. 密钥轮换策略

每个密钥版本（`keys.Version`）一旦加入密钥环即不可变，由 `ID + Secret +
CreatedAt + ExpiresAt + RetireAt` 描述，在任意时刻处于以下三态之一：

| 状态    | 时间条件                    | 能否签发 | 能否验签 |
|---------|-----------------------------|----------|----------|
| active  | `now < ExpiresAt`           | 是       | 是       |
| grace   | `ExpiresAt <= now < RetireAt` | 否     | 是       |
| retired | `now >= RetireAt`           | 否       | 否       |

- **多版本共存**：轮换（`KeyRing.Rotate`）只是加入新版本并把它设为 active，
  旧版本继续留在环中用于验签。有效期内，多个密钥签发的令牌都能通过验证。
- **过渡期语义（确定且可说明）**：旧密钥到达 `ExpiresAt` 后进入 grace 宽限窗口，
  不能再签发，但**在宽限窗口内、且令牌自身未过期时，旧密钥签发的令牌仍被接受**。
  到达 `RetireAt` 后旧密钥 retired，其令牌一律拒绝（错误码 `key_retired`），
  即使令牌自身的 `exp` 尚未到。宽限长度由轮换时的 `grace` 参数决定。
- **不会静默用过期密钥签发**：active 密钥一旦越过 `ExpiresAt`，`Active()` 返回
  `ErrNotActive`，强制调用方先轮换。
- 令牌头部带 `kid`；验签时按 `kid` 取密钥，因此新旧令牌可并存且互不干扰。

### 验签失败的固定判定优先级（原因可区分）

1. `token_malformed`：段数/编码/JSON/算法/`kid` 缺失等结构问题
2. `unknown_key_version`：`kid` 在密钥环中根本不存在
3. `key_retired`：密钥版本已过 `RetireAt`
4. `signature_mismatch`：HMAC 不匹配（密钥版本已知且未退役）
5. `token_expired`：签名正确但已过令牌自身的 `exp`

## 2. 刷新与重放规则

登录创建一条**会话链（chain）**的根节点；每次成功的刷新：

1. 校验并**一次性消费**旧的刷新凭据（`Used=true`）；
2. 签发新的访问令牌与新的不透明刷新凭据（256bit 随机数，本身无含义）；
3. 在同一条链上追加一个新会话，`roles/scopes` **原样继承链根**，调用方无法在
   刷新时传入或扩大权限。

旧凭据不会立即删除，而是保留索引以便识别重放。刷新结论是确定的：

| 输入情形                         | 错误码                | 状态影响 |
|----------------------------------|-----------------------|----------|
| 凭据不存在                        | `refresh_not_found`   | 无       |
| 所属链已被终止                    | `refresh_replayed`    | 无       |
| 同一凭据已有刷新在进行中          | `concurrent_refresh`  | 无       |
| 凭据已被消费（再次出现）          | `refresh_replayed`    | **撤销整条链** |
| 凭据未消费但已过期                | `refresh_expired`     | 无       |
| 正常                              | 成功，轮换恰好一次     | 追加 1 个会话 |

- **重放即终止链路**：已使用过的旧凭据再次出现，判定为一次性使用违例，链上所有
  会话标记 `Revoked`。之后链上任何凭据（包括刚轮换出的「新」凭据）再使用都得到
  `refresh_replayed`，不会产生重复会话或状态分叉。
- **并发刷新只允许一个成功**：服务以全局互斥串行化状态变更，并对「正在轮换」的
  凭据维护 in-flight 预留。N 个并发请求中恰好 1 个成功，其余得到
  `concurrent_refresh` 且不改变任何状态；提交阶段会在锁内二次校验，防止准备期间
  链被其他重放终止。测试用 32/16 goroutine + `-race` 验证无分叉、无重复会话。

## 3. 会话终止与容量上限

访问令牌在签发时通过 `cid` claim 绑定所属会话链（`tokens.Claims.ChainID`），因此
链一旦被终止，**链上已签发的访问令牌立即失效**（`Authenticate` 在校验签名之后、
返回 claims 之前检查链状态），结论为 `session_revoked`。

### 主动登出（`Logout` / `POST /logout`）

凭**任意一个属于该链的刷新凭据**（包括登录时最初下发的那个）即可结束整条链：

| 输入情形               | 结论                | 状态影响 |
|------------------------|---------------------|----------|
| 凭据不存在/为空         | `refresh_not_found` | 无       |
| 链上任意凭据            | 成功，整链撤销       | 链终止   |
| 链已终止（重复登出）     | **幂等成功**，不报错 | 无       |

登出后链上任何凭据再刷新都得到固定的 `session_revoked`——与「凭据从来没出现过」
的 `refresh_not_found` 明确区分；同一主体的其他链不受影响。

### 按主体终止（`TerminateSubject` / `POST /terminate`）

一次性撤销某主体当前所有存活链，返回本次终止的链数。并发语义是确定的：

- 整个终止在状态锁内原子完成；`Refresh` 的提交阶段在同一把锁内二次校验链状态。
  因此**终止返回后，该主体名下不可能再有刷新成功**，在终止进行中的刷新要么已经
  提交（属于被终止的历史），要么在提交时发现链已撤销而失败——不存在「终止完成了
  但某个并发请求又把链路续上」的窗口，结论不随 goroutine 调度变化。
- 终止不封禁主体：之后可以重新登录建立新链。
- 测试（`TestTerminateRacesWithRefresh`）用 8 条链并发狂刷 + 中途终止验证：终止
  返回时快照的链会话数之后不再变化（不多不少），所有最新凭据刷新均为
  `session_revoked`。

### 每主体活跃链上限（`Options.MaxChainsPerSubject`）

- 上限只统计**存活**链；`<= 0` 表示不限。
- 达到上限后登录被明确拒绝：`session_limit_exceeded`（HTTP 429），与凭证错误、
  重放等其他失败原因可区分。
- 登出或按主体终止后配额**立即**腾出，可以重新登录。
- 容量检查与占用在同一临界区内完成：16 并发登录抢 cap=4 时恰好 4 个成功；
  登出与登录混合并发时，最终存活链数严格等于「成功登录数 − 成功登出数」，
  绝不超过上限（`TestConcurrentLoginLogoutRespectsCap`）。

### 兼容范围

- 访问令牌新增 `cid`（链 ID）claim，带 `omitempty`：本服务签发的令牌都携带；
  不含 `cid` 的旧格式令牌仍按原规则验签，只是不参与「链终止即失效」判定。
- 原有结论不变：重放终止链仍报 `refresh_replayed`，未知凭据仍报
  `refresh_not_found`；登出/按主体终止的链统一报 `session_revoked`，三者可区分。
- `Options.MaxChainsPerSubject <= 0`（默认）行为与上一版完全一致（不限链数）。

## 4. 鉴权模型

`authz.Policy` 维护 `角色 -> 作用域集合`；令牌携带 `roles` 与 `scopes`，请求可
声明所需角色与作用域。鉴权结论是**四值**的，严格区分「你是谁无法确认」与
「知道你是谁，但你不能做」：

| 判定                      | 含义                              | HTTP |
|---------------------------|-----------------------------------|------|
| `allow`                   | 认证通过且满足全部角色/作用域要求  | 200  |
| `deny_no_credentials`     | 完全没有提供令牌                   | 401 `missing_token` |
| `deny_unauthenticated`    | 令牌无法通过验证（过期/签名错/密钥未知或退役/畸形） | 401 + 具体错误码 |
| `deny_forbidden`          | 身份已验证，但缺少所需角色或作用域 | 403 `forbidden` |

作用域来源 = 令牌自带 `scopes` ∪ 其 `roles` 在策略中授予的作用域。由于刷新只做
权限继承，**刷新后得到的权限不可能超出最初授权范围**（`auth` 与 `authz` 两层
都有测试）。判定过程无惰性读写，并发请求下结论稳定（见
`TestConcurrentDecisionsStable`）。

## 5. HTTP API

`cmd/idp` 启动后监听 `:8080`（可用 `IDP_ADDR` 覆盖），所有接口均为 `POST` JSON：

- `POST /login`   `{subject, roles?, scopes?}` → `access_token, refresh_token, key_id, ...`；超出每主体链上限时 429 `session_limit_exceeded`
- `POST /refresh` `{refresh_token}` → 轮换后的新令牌对
- `POST /logout`  `{refresh_token}` → `{"terminated":true}`；幂等，未知凭据 401 `refresh_not_found`
- `POST /terminate` `{subject}` → `{"terminated_chains":N}`，终止该主体全部存活链
- `POST /verify`  `{access_token}` → 令牌 claims，或带错误码的 401（链已终止时为 `session_revoked`）
- `POST /authz`   `{access_token, roles?, scopes?}` → `{decision:"allow",...}` 或 401/403

错误响应统一形如 `{"error":"<code>","reason":"<可解释原因>"}`。

## 6. 本地验证

```bash
# 运行全部测试（含竞态检测）
go test ./... -race -v

# 只看关键场景
go test ./internal/keys/  -v   # 轮换、active/grace/retired 三态
go test ./internal/tokens/ -v # 多版本共存、宽限、过期/签名/未知/退役区分
go test ./internal/auth/  -v   # 一次性轮换、重放终止链、登出/按主体终止、容量上限、并发竞争
go test ./internal/authz/ -v   # 四值判定、权限不扩散、并发稳定
go test ./internal/server/ -v  # HTTP 端到端、401/403/429 区分

# 启动服务并手工验证
go run ./cmd/idp
```

另开一个终端：

```bash
BASE=http://localhost:8080
LOGIN=$(curl -s -XPOST $BASE/login \
  -d '{"subject":"alice","roles":["editor"],"scopes":["read","write"]}')
AT=$(echo "$LOGIN" | jq -r .access_token)
RT=$(echo "$LOGIN" | jq -r .refresh_token)

curl -s -XPOST $BASE/verify -d "{\"access_token\":\"$AT\"}"
curl -s -XPOST $BASE/authz  -d "{\"access_token\":\"$AT\",\"scopes\":[\"write\"]}"   # allow
curl -s -XPOST $BASE/authz  -d "{\"access_token\":\"$AT\",\"scopes\":[\"admin\"]}"   # 403 forbidden
curl -s -XPOST $BASE/authz  -d '{}'                                                  # 401 missing_token

NEW=$(curl -s -XPOST $BASE/refresh -d "{\"refresh_token\":\"$RT\"}")
curl -i -XPOST $BASE/refresh -d "{\"refresh_token\":\"$RT\"}"   # 401 refresh_replayed，链路终止

# 登出：用最初下发的刷新凭据结束当前链（幂等）
RT2=$(echo "$NEW" | jq -r .refresh_token)
AT2=$(echo "$NEW" | jq -r .access_token)
curl -s -XPOST $BASE/logout -d "{\"refresh_token\":\"$RT2\"}"          # {"terminated":true}
curl -s -XPOST $BASE/verify -d "{\"access_token\":\"$AT2\"}"           # 401 session_revoked
curl -s -XPOST $BASE/refresh -d "{\"refresh_token\":\"$RT2\"}"         # 401 session_revoked
curl -s -XPOST $BASE/logout -d "{\"refresh_token\":\"$RT2\"}"          # 仍是 200（幂等）

# 按主体一次性终止：该主体所有存活链立即失效
curl -s -XPOST $BASE/login -d '{"subject":"alice"}' >/dev/null
curl -s -XPOST $BASE/terminate -d '{"subject":"alice"}'                # {"terminated_chains":N}
```

服务端日志（stdout）与 `go test -v` 都会打印**关键输入与判定依据**：密钥版本、
角色/作用域、凭据前缀（只打印前 12 字符，避免泄露完整密钥）、得到的状态/错误码
及原因。

> 说明：本项目用于本地演练与语义验证，进程内状态不做持久化；生产环境需要替换为
> 持久化且带原子 CAS 的存储，并把密钥密文托管到 KMS。
