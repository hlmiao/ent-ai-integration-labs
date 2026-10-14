# Enterprise OIDC × Volcengine AgentKit Headless SSO POC 验证报告

> 公开脱敏版本：客户名称、域名、账号、资源 ID、请求 ID、用户信息和凭证均已移除或替换为占位符。

| 项目 | 内容 |
|---|---|
| 测试环境 | Enterprise OIDC Test Environment / Volcengine `cn-beijing` |
| 验证日期 | `<validation-date>` |
| 验证状态 | 端到端链路通过 |
| 验证范围 | Device Code、MFA、OIDC ID Token、Token Exchange、MCP JWT 鉴权与工具调用 |

## 1. 执行摘要

本次 POC 已完成以下端到端链路验证：

```text
Enterprise 用户登录与 MFA
  → Enterprise OIDC ID Token
  → Volcengine UserPool Token Exchange
  → Volcengine Access Token
  → AgentKit MCP Gateway JWT 鉴权
  → MCP tools/call
```

最终结果：

- Enterprise OIDC Test Environment 成功签发 RS256 OIDC ID Token。
- Volcengine UserPool 成功完成外部身份 Token Exchange。
- AgentKit MCP Gateway 成功验证换取的 Access Token。
- MCP `initialize`、会话初始化和 `tools/call` 均成功。
- 最终工具调用返回 HTTP 200，业务结果 `isError=false`。

本方案中的 Headless 指：用户完成一次登录、MFA 和 Consent 后，Token
Exchange 与 MCP 调用均由后端通过 API 完成，不依赖浏览器重定向回业务客户端。

## 2. 验证范围与边界

### 2.1 已验证

- OIDC Discovery 与 JWKS 获取
- Device Authorization Grant
- 用户登录、MFA 与 Consent
- RS256 ID Token 签发及本地验签
- 外部身份 Token Exchange
- UserPool 用户自动创建与关联配置
- MCP Gateway CustomJWT 验签
- MCP 会话初始化
- MCP 工具调用
- 无 Token、错误 Audience 等负向鉴权行为

### 2.2 本次未覆盖

- 生产环境高可用与容量评估
- Refresh Token 生命周期与吊销策略
- 生产密钥托管与自动轮换
- 全量用户属性、部门和用户组映射
- 多地域、私网发布和灾备
- 长时间稳定性与并发压测

## 3. 架构与信任边界

### 3.1 逻辑链路

```text
企业用户
  │  Device Code 页面登录、MFA、Consent
  ▼
Enterprise OIDC IdP
  │  RS256 ID Token
  ▼
企业后端
  │  ExternalIdentityProviderTokenExchange
  ▼
Volcengine UserPool
  │  Access Token
  ▼
AgentKit MCP Gateway
  │  CustomJWT + AllowedClients
  ▼
MCP sequential-thinking-server
```

### 3.2 客户端职责分离

| 客户端 | 类型 | 职责 |
|---|---|---|
| Enterprise Device Client | Device OIDC Client | 获取企业用户 ID Token |
| Volcengine Token Exchange Client | Web Application | 使用外部 ID Token 换取火山 Access Token |
| Volcengine M2M Client | Machine-to-Machine | 仅用于服务身份和网关鉴权探测 |

Enterprise Client 与 Volcengine Client 属于不同信任域，不共享 Client ID
或 Client Secret。

## 4. 关键配置

### 4.1 Enterprise OIDC Test Environment

| 配置 | 值 |
|---|---|
| Issuer | `https://idp.example.com` |
| Device Client ID | `enterprise-device-client-id` |
| Scope | `openid profile` |
| 本次成功 Token 算法 | `RS256` |

Discovery 当前声明支持 `RS256` 和 `ES256`，JWKS 同时发布 RSA 与 EC 公钥。

### 4.2 Volcengine UserPool

| 配置 | 值 |
|---|---|
| Region | `cn-beijing` |
| UserPoolUid | `user-pool-uid` |
| Token Exchange ConnectionUid | `token-exchange-connection-uid` |
| Web Application Client ID | `volcengine-web-client-id` |
| Allowed Audience | Enterprise Device Client ID |
| Claims Propagation | `FULL` |
| 自动创建/关联/更新 | 已启用 |

### 4.3 AgentKit MCP

| 配置 | 值 |
|---|---|
| MCPServiceId | `mcp-service-id` |
| Path | `/mcp` |
| Inbound Authorizer | `CustomJWT` |
| Web Client Audience | `volcengine-web-client-id` |
| Backend | `sequential-thinking-server` |

## 5. 测试过程与结果

| 序号 | 测试项 | 结果 | 判定 |
|---|---|---|---|
| 1 | Enterprise Discovery/JWKS | 端点可访问 | 通过 |
| 2 | Device Code 申请 | 返回验证地址与用户码 | 通过 |
| 3 | 用户登录、MFA、Consent | 完成授权 | 通过 |
| 4 | Enterprise ID Token | RS256，Issuer/Audience/KID 匹配 | 通过 |
| 5 | 本地 JWT 验签 | 使用 Enterprise JWKS 验签成功 | 通过 |
| 6 | UserPool Token Exchange | HTTP 200 | 通过 |
| 7 | 火山 Access Token | 成功签发，有效期 `35999` 秒 | 通过 |
| 8 | MCP 错误 Audience | HTTP 401，`jwt_auth:invalid_audience` | 符合预期 |
| 9 | 更新 MCP AllowedClients | Update API HTTP 200 | 通过 |
| 10 | MCP `initialize` | HTTP 200 | 通过 |
| 11 | MCP initialized notification | HTTP 202 | 通过 |
| 12 | MCP `tools/call` | HTTP 200，`isError=false` | 通过 |

最终 MCP 返回：

```json
{
  "thoughtNumber": 1,
  "totalThoughts": 1,
  "nextThoughtNeeded": false,
  "branches": [],
  "thoughtHistoryLength": 1
}
```

## 6. Token 验证证据

### 6.1 上游 Enterprise ID Token

```text
alg: RS256
kid: <rsa-key-id>
iss: https://idp.example.com
aud: enterprise-device-client-id
有效期: 约 5 分钟
```

完整 Token、用户标识和个人信息不在本文档中展示。

### 6.2 Token Exchange 返回

```text
HTTP status: 200
TokenType: Bearer
ExpiresIn: 35999
返回字段:
  - AccessToken
  - IdToken
  - RefreshToken
```

### 6.3 Volcengine Access Token

```text
alg: RS256
iss: Volcengine UserPool Issuer
aud: volcengine-web-client-id
client_id: volcengine-web-client-id
scope: openid offline_access
```

## 7. 关键问题与处理结果

### 7.1 ES256 兼容性

初始测试使用 Enterprise ES256 ID Token 时，UserPool 返回：

```text
external identity provider token is invalid or expired
```

经双方排查确认，当前 UserPool 外部 OIDC ID Token verifier 需要 RS256。
Enterprise OIDC Test Environment 随后签发 RS256 ID Token，相同 Token Exchange 配置下
立即返回 HTTP 200。

当前 POC 采用 RS256 作为有效兼容路径。若后续恢复使用 ES256，需要先确认
UserPool 已正式支持并完成回归验证。

### 7.2 MCP Audience 白名单

Token Exchange 成功后，初次 MCP 调用返回：

```text
HTTP 401
x-auth-failure: jwt_auth:invalid_audience
```

将 Web Application Client ID 加入 MCP `AllowedClients` 后，JWT 鉴权通过。

### 7.3 控制面回读延迟

`UpdateMCPService` 返回 HTTP 200 后，首次 `GetMCPService` 仍返回旧白名单，
但数据面已接受新 Audience。后续自动化脚本已增加有限次数回读重试，以处理
控制面短暂延迟。

## 8. 安全控制

- Client Secret 仅通过隐藏输入或安全环境变量注入。
- 源码和文档不包含 Client Secret、AK/SK 或完整 Token。
- 云资源管理支持现有 STS、最小权限 AK/SK 或可选 AssumeRole；生产环境优先使用短期凭证。
- 临时 Token 文件权限设置为 `0600`。
- 诊断日志仅记录 Token SHA-256 指纹和脱敏 Claims。
- MCP Gateway 使用 JWT Audience 白名单限制调用客户端。
- 用户登录阶段由 Enterprise 执行 MFA。

## 9. 生产化建议

1. 固化 Enterprise 与 Volcengine 之间的签名算法约定，当前采用 RS256。
2. 使用专用 Web Application Client 承载用户 Token Exchange。
3. 对 Client Secret、RSA 私钥和 Refresh Token 使用企业级密钥托管。
4. 明确 Access Token 与 Refresh Token 的有效期、轮换、吊销和异常退出策略。
5. 确认生产 Token 必需包含稳定 `sub`，并补齐 `email`、部门和用户组 Claims。
6. 将 Claims 映射和业务授权规则纳入独立验收，不仅验证“可调用”。
7. 分别核对公网与私网发布的 JWT Authorizer 和 `AllowedClients`。
8. 建立 Token Exchange、JWT 拒绝原因、MCP 调用失败率和审计事件监控。
9. 上线前轮换全部测试凭证，并清理本地临时 Token 与诊断文件。
10. 对生产链路执行并发、故障恢复、密钥轮换和 JWKS 缓存刷新测试。

## 10. 最终结论

本次 POC 已证明以下能力可行：

> Enterprise 企业用户通过 Device Code、MFA 和 Consent 完成身份认证后，
> 企业后端可使用 Enterprise RS256 OIDC ID Token，通过 Volcengine
> UserPool Token Exchange 获取火山 Access Token，并通过 AgentKit MCP
> Gateway 的 JWT 鉴权调用受保护工具。

端到端功能验证已通过。正式上线前仍需完成 Claims 与业务授权映射、令牌生命
周期、密钥管理、监控审计和生产环境非功能验证。
