# local-kms：本地密钥签名与校验服务

在本地状态中保存密钥版本与请求流水，提供密钥轮转、请求签名、重放判定与
密钥材料封存/恢复能力。全部功能离线可复现，不依赖任何外部服务。

## 快速开始

```bash
uv sync
uv run pytest            # 运行全部测试（日志含输入与判定依据）
uv run uvicorn main:app  # 启动 HTTP 服务（默认状态文件 keystore_state.json）
```

## 密钥状态与轮转规则

每个密钥（`key_id`）由递增的版本链组成，版本状态机如下：

```
PENDING ──activate──> ACTIVE ──rotate/transition──> VERIFY_ONLY ──过渡期结束──> REVOKED
   │                    │                                │
   └──────revoke────────┴────────────revoke──────────────┘
```

| 状态 | 可签名 | 可验签 | 允许的迁移 |
|---|---|---|---|
| `pending` | 否 | 否 | `active`、`revoked` |
| `active` | 是 | 是 | `verify_only`、`revoked` |
| `verify_only` | 否 | 是（过渡期内） | `revoked` |
| `revoked` | 否 | 否 | 无（终态） |

- **轮转**（`rotate`）：当前 `active` 版本进入 `verify_only` 并记录过渡期截止
  时间 `verify_only_until = now + transition_seconds`，同时生成新版本直接置为
  `active`。轮转后新请求一律用当前 `active` 版本签名。
- **过渡期边界**：`now < verify_only_until` 时历史版本可验签；到达边界即拒绝
  （`transition_expired`），随后 `refresh()` 将其自动置为 `revoked`。
- **非法迁移**（如 `active→pending`、`revoked→active`）抛出
  `IllegalTransitionError`，HTTP 层返回 409。
- 状态落盘于本地 JSON（原子写入：临时文件 + `os.replace`），重启后可恢复。

## 请求签名与重放防护

- 算法：**Ed25519**。签名覆盖规范化字节：方法、key_id、版本、时间戳、
  随机数与关键负载（长度前缀拼接，无歧义）。
- 验签按固定顺序检查，失败原因可区分：

| 顺序 | 检查 | 失败原因 |
|---|---|---|
| 1 | 密钥/版本存在 | `key_not_found` |
| 2 | 密钥状态 | `key_pending` / `key_revoked` / `transition_expired` |
| 3 | 时间窗（默认 ±300s） | `timestamp_out_of_window` |
| 4 | 签名匹配 | `signature_mismatch` |
| 5 | 随机数未使用 | `nonce_reused` |

- 先验签后记 nonce：伪造签名的请求不会污染 nonce 流水（防 DoS）。
- nonce 记录按时间窗淘汰（`ts < now - window` 即删除），长期运行不无界增长。
- 签名、验签、轮转共用同一把可重入锁：轮转与验签并发时，单个请求的判定
  是原子的，不会既通过又被拒绝。

## 封存与恢复（口令派生参数）

导出包含私有材料的归档时，使用口令派生密钥加密：

| 参数 | 值 |
|---|---|
| KDF | PBKDF2-HMAC-SHA256 |
| 迭代次数 | 200,000 |
| 盐 | 16 字节随机 |
| 加密 | AES-256-GCM（nonce 12 字节随机） |
| 归档格式 | `kms-sealed-v1`（JSON 信封：kdf 参数 + nonce + 密文） |

- **口令错误或密文被篡改**：AES-GCM 认证失败，统一抛 `WrongPassphraseError`，
  不返回任何部分明文。
- **归档结构损坏或版本关系不完整**（指纹不复现、版本号不连续、前驱链接断裂）
  抛 `CorruptArchiveError`。
- 恢复时逐版本重算公钥指纹（`sha256:<hex>`）并校验版本链，保证可复现。

### 验证方法

```bash
uv run pytest tests/test_vault.py -v   # 错误口令/篡改密文/断链用例
uv run pytest -k transition            # 过渡期边界
uv run pytest tests/test_concurrency.py -v  # 并发重复 nonce 与轮转并发
```

## HTTP 接口摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/keys/{key_id}` | 创建密钥（v1, pending） |
| POST | `/keys/{key_id}/versions/{v}/activate` | 启用版本 |
| POST | `/keys/{key_id}/rotate` | 轮转（`transition_seconds`） |
| POST | `/keys/{key_id}/versions/{v}/revoke` | 吊销版本 |
| POST | `/sign` | 用当前 active 版本签名 |
| POST | `/verify` | 验签，返回 `ok`/`reason`/`detail` |
| POST | `/export` / `/restore` | 封存导出与恢复 |

环境变量：`KMS_STATE_PATH`（状态文件路径）、`KMS_WINDOW_SECONDS`（时间窗）。
