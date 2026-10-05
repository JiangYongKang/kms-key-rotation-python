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
- 签名、验签、轮转共用同一把可重入锁：轮转与验签并发时，单个请求的判定
  是原子的，不会既通过又被拒绝。

## 请求流水：保留期与容量策略

验签通过的请求写入请求流水（随状态文件一起落盘），既用于重放判定，也用于
审计对账。两条可配置的保护：

| 配置 | 环境变量 / 构造参数 | 默认 | 语义 |
|---|---|---|---|
| 保留期 | `KMS_LEDGER_RETENTION_SECONDS` / `ledger_retention_seconds` | 取验签时间窗 | 保留期内的记录**绝不**因清理被提前删除 |
| 容量上限 | `KMS_LEDGER_MAX_RECORDS` / `ledger_max_records` | 100000 | 流水条数硬上限 |

- 保留期会被自动提升到不短于验签时间窗，保证窗口内的重放判定不丢记录。
- 清理是惰性的 O(n) 过滤，随记录动作摊销（也可显式 `sweep_ledger()` /
  `POST /ledger/sweep`），不长时间卡住签名与验签。
- **容量顶满且清理不出保留期外的记录时，新请求被明确拒绝**，失败原因为
  `ledger_capacity_exceeded`，与 `nonce_reused`、`signature_mismatch` 等
  其它原因可区分；不静默丢弃、不无界增长。被拒绝的请求不占用 nonce，
  腾出空间后重提可正常受理。

## 多进程与重启

- 状态文件为单一 JSON 文档（`kms-state-v2`）：密钥版本与请求流水写在同一份
  文件里，原子落盘（临时文件 + `os.replace` + `fsync`），**两边要么一起
  生效要么一起不生效**，重启后不会出现密钥已轮转但流水丢失（或反之）。
- 所有变更（生命周期迁移、验签记流水）在跨进程事务内完成：对
  `<状态文件>.lock` 加排他文件锁（`flock`）→ 从磁盘重载 → 变更 → 原子
  落盘 → 释放。多个工作进程共用同一状态文件时，**同一 nonce 最多被一个
  进程放行**；进程重启后，之前已通过的请求再提交仍判 `nonce_reused`。
- 查询与导出走共享锁只读重载，不落盘，不改变任何判定状态。
- **兼容范围**：旧版状态文件（v1 裸密钥字典、无流水）加载时自动识别、
  保存时自动升级为 v2，无需清空或人工迁移；之前导出的封存归档
  （`kms-sealed-v1`）格式不变，可继续恢复。

## 审计查询与对账导出

- **查询**：`service.query_ledger(key_id=, version=, start=, end=)` 或
  `GET /ledger?key_id=&version=&start=&end=`，按密钥、版本、判定时间范围
  过滤；每条记录含结论（`decision`）与判定依据（`basis`，如
  `key_state=active; timestamp_in_window; signature_ok; nonce_fresh`）。
- **导出**：`service.export_ledger_manifest()` 或 `GET /ledger/export`，
  生成 `kms-ledger-export-v1` 清单：记录按 `(decided_at, nonce)` 排序、
  键序固定，**重复导出字节完全一致**；附 `sha256` 摘要（对记录数组的
  规范化 JSON 计算），可离线重算核对；不含任何私钥材料。
- 查询与导出均为只读操作，不改变任何判定状态。

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
uv run pytest tests/test_multiprocess.py -v # 多进程/重启重复判定、旧格式兼容
uv run pytest tests/test_ledger.py -v  # 保留期/容量边界、审计查询与导出
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
| GET | `/ledger` | 按密钥/版本/时间范围查询请求流水（只读） |
| GET | `/ledger/export` | 导出确定性对账清单（无私钥，含 sha256 摘要） |
| POST | `/ledger/sweep` | 主动清理保留期外的流水记录 |

环境变量：`KMS_STATE_PATH`（状态文件路径）、`KMS_WINDOW_SECONDS`（时间窗）、
`KMS_LEDGER_RETENTION_SECONDS`（流水保留期）、`KMS_LEDGER_MAX_RECORDS`
（流水容量上限）。
