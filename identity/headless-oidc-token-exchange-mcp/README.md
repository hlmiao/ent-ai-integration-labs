# Headless OIDC Token Exchange for Volcengine AgentKit MCP

本项目演示企业 OIDC 用户通过 Device Authorization Grant 完成登录与 MFA，
随后由后端使用外部 ID Token 调用 Volcengine UserPool Token Exchange，并使用
换得的 Access Token 调用 AgentKit MCP。

```text
Enterprise OIDC IdP
  → Device Code + MFA + Consent
  → External OIDC ID Token
  → Volcengine UserPool Token Exchange
  → Volcengine Access Token
  → AgentKit MCP Gateway
  → tools/call
```

## 安全边界

- 用户交互仅发生在企业 IdP 登录、MFA 和 Consent 阶段。
- Token Exchange 与 MCP 调用为后端 API 链路。
- 企业 IdP Client 与 Volcengine Client 属于不同信任域，不可混用。
- 仓库不应保存 Client Secret、AK/SK、STS Token 或任何完整 JWT。

## 文件说明

```text
scripts/
  device_client.py                 Device Code 客户端
  exchange_token.py                UserPool Token Exchange 客户端
  volc_auth.py                     Volcengine OpenAPI 通用鉴权
  create_te_connection.py          创建 Token Exchange 连接
  update_te_connection.py          更新 Token Exchange 连接
  update_mcp_allowed_clients.py    更新 MCP AllowedClients
  whoami.py                        查询 Volcengine 调用身份

docs/
  validation-report.md             脱敏验证报告
  headless-sso-architecture.drawio 架构图源文件
  headless-sso-architecture.png    架构图预览
```

## 1. 获取外部 ID Token

```bash
export IDP_BASE="https://idp.example.com"
export CLIENT_ID="<enterprise-device-client-id>"
export CLIENT_SECRET_REQUIRED="1"
export SCOPE="openid profile"

python3 scripts/device_client.py
```

如使用 public client，可不设置 `CLIENT_SECRET_REQUIRED`。

默认输出：

```text
/tmp/external_id_token.txt
```

## 2. 执行 Token Exchange

```bash
export VOLC_USER_POOL_UID="<user-pool-uid>"
export TOKEN_EXCHANGE_CONNECTION_UID="<connection-uid>"
export VOLC_CLIENT_ID="<volcengine-web-client-id>"

python3 scripts/exchange_token.py
```

脚本会隐藏提示输入 Volcengine Client Secret。

默认输出：

```text
/tmp/volc_identity_token.txt
/tmp/token_exchange_diagnostic.log
```

## 3. 管理面鉴权

脚本支持三种模式。

现有 STS 临时凭证：

```bash
export VOLC_ACCESSKEY="<temporary-access-key>"
export VOLC_SECRETKEY="<temporary-secret-key>"
export VOLC_SESSIONTOKEN="<session-token>"
```

直接 AK/SK：

```bash
export VOLC_ACCESSKEY="<access-key>"
export VOLC_SECRETKEY="<secret-key>"
```

可选 AssumeRole：

```bash
export VOLC_ROLE_TRN="<role-trn>"
```

生产环境优先使用短期 STS 凭证，并遵循最小权限原则。

## 4. 配置 Token Exchange

创建连接：

```bash
export VOLC_USER_POOL_UID="<user-pool-uid>"
export EXTERNAL_OIDC_ISSUER="https://idp.example.com"

python3 scripts/create_te_connection.py
```

更新连接：

```bash
export VOLC_USER_POOL_UID="<user-pool-uid>"
export VOLC_TE_CONNECTION_UID="<connection-uid>"
export EXTERNAL_OIDC_ISSUER="https://idp.example.com"
export EXTERNAL_ALLOWED_AUDIENCE="<enterprise-device-client-id>"

python3 scripts/update_te_connection.py
```

更新 MCP Audience 白名单：

```bash
export VOLC_MCP_SERVICE_ID="<mcp-service-id>"
export VOLC_ALLOWED_CLIENTS="<volcengine-web-client-id>"

python3 scripts/update_mcp_allowed_clients.py
```

## 5. 签名算法

外部 IdP 的签名算法必须被 UserPool 外部 Token verifier 支持。本次公开示例使用
RS256。使用 ES256 前，应先确认目标环境已提供对应支持。

## 6. 运行要求

- Python 3.9+
- 仅使用 Python 标准库
- 可访问企业 OIDC、Volcengine UserPool 和 AgentKit MCP Endpoint
- 所有运行时凭证通过安全环境变量或隐藏输入注入
