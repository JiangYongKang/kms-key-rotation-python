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
- 签名、验签、轮转共用同一把锁；多进程部署时再加文件锁互斥（见下节）。

## 多进程部署、重启一致性与状态原子性

多个工作进程（或同一台机器上的多个实例）把 `KMS_STATE_PATH` 指向**同一个状态
文件**即可安全共用：

- **跨进程互斥**：进程内用可重入锁，进程间用同目录 `keystore_state.json.lock`
  上的 `flock` 排他锁。每次进入签名/验签/轮转/封存段时先拿文件锁，**再重读
  磁盘**，保证看到其它进程刚刚提交的最新状态。
- **同一 nonce 全局限一次**：由于判定与落盘都在文件锁内，N 个进程同时提交同一
  nonce，恰有一个判 `accepted`，其余全部 `nonce_reused`。
- **重启结论不变**：每条判定（接受/重放及依据）都随状态落盘；进程重启后重新
  加载，保留期内已接受过的 nonce 再次提交仍然判重复，不会因换进程或重载而放行。
- **原子共写**：密钥版本与请求流水在同一次原子写入（临时文件 + `fsync` +
  `os.replace`）中一起生效，要么都生效、要么都不生效，重启后两边不会对不上。
- **向后兼容**：旧的无 `format` 字段的状态文件可直接读取，首次写操作自动升级
  为 `kms-state-v2`，无需清空状态或人工迁移；此前导出的 `kms-sealed-v1`
  封存归档也可继续恢复进新状态。

> 兼容范围：多进程指共享同一文件系统的本地部署（`flock` 依赖操作系统的文件
> 锁）。不跨主机、不依赖网络存储的锁语义。

## 流水保留期与容量策略

请求流水（nonce journal）的两个上限都可配置：

| 配置 | 环境变量 | 构造参数 | 默认 |
|---|---|---|---|
| 保留期 | `KMS_RETENTION_SECONDS` | `retention_seconds` | 等于时间窗（300s） |
| 容量上限（条） | `KMS_NONCE_CAPACITY` | `nonce_capacity` | 1,000,000 |

规则：

- **保留期只约束过期记录**：仅当 `recorded_at < now - retention` 的记录才允许
  被清理，时间窗内的记录绝不会被提前丢掉，因此本该判重的请求不会被放行。
  构造时强制 `retention_seconds >= window_seconds`，否则直接报错（短于时间窗
  会产生重放漏洞）。
- **容量打满显式拒绝**：容量统计的是“保留期内已接受的 nonce 集合”（防重放
  状态本身）。当集合打满、又没有过期记录可腾退时，携带**新 nonce** 的请求被
  明确拒绝，原因 `nonce_log_full`（HTTP 503），与其它失败区分；不会静默丢弃，
  也不会无界增长。
- **重放请求不占容量**：被拒的重放记录只受保留期约束、不增加已接受集合，
  因此攻击者无法用重放把容量顶满来误伤合法新请求；容量满时重放仍照常判
  `nonce_reused`。
- **清理不拖慢正常路径**：记录按 `(recorded_at, seq)` 有序保存，清理只切
  有序前缀（不做全表扫描）；也可调用 `service.refresh()` 显式推进生命周期并
  清理过期流水。

## 审计查询与对账导出

查询与导出都是**只读**的，不改变任何判定状态：

```python
service.query_records(key_id="k",            # 可按密钥
                      version=2,             # 版本
                      start=1000.0, end=..)  # recorded_at 时间范围（含端点）
# -> NonceRecord 列表，每条含 seq / key_id / version / nonce /
#    timestamp / recorded_at / outcome(accepted|replayed) / basis（判定依据）

blob = service.export_audit()                # bytes：离线对账清单
```

- 导出格式 `kms-audit-v1`：包含密钥的**公钥指纹与状态**、每条记录的结论与
  判定依据，以及整体摘要 `digest`。**不含任何私钥明文**（密钥项的私钥字段
  标记为 `"sealed"`）。
- **稳定可复现**：记录按全局单调 `seq` 排序，JSON 确定性序列化、无随机字段，
  同一底层状态下重复导出得到**字节完全一致**的结果；重启加载后导出也一致。
- **离线核对**：`Auditor.verify_digest(blob)` 重算正文摘要与清单内 `digest`
  比对，清单被改动即可被发现。

HTTP 接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/audit/records?key_id=&version=&start=&end=` | 条件查询流水（只读） |
| GET | `/audit/export` | 导出对账清单（`blob_b64` + `digest`，只读） |


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
| POST | `/verify` | 验签，返回 `ok`/`reason`/`detail`（容量满返回 503） |
| POST | `/export` / `/restore` | 封存导出与恢复 |
| GET | `/audit/records` / `/audit/export` | 流水查询与对账导出（只读） |

环境变量：`KMS_STATE_PATH`（状态文件路径）、`KMS_WINDOW_SECONDS`（验签时间
窗）、`KMS_RETENTION_SECONDS`（流水保留期，默认等于时间窗）、
`KMS_NONCE_CAPACITY`（流水容量上限，默认 1,000,000）。

### 本地复现验证

```bash
uv sync
uv run pytest -q                                   # 全量单测（日志打印输入与判定依据）
uv run pytest tests/test_persistence.py -v        # 重启判重、8 进程竞争、原子提交、旧格式/旧归档兼容
uv run pytest tests/test_retention.py -v          # 保留期保护、容量打满拒绝、过期腾退
uv run pytest tests/test_audit.py -v              # 查询过滤、导出确定性/摘要/无私钥、只读
uv run pytest tests/test_lifecycle.py tests/test_concurrency.py -v  # 轮转/封存/并发不回归
```

多进程行为可直接观察：多个 worker 把 `KMS_STATE_PATH` 指向同一文件，
`tests/test_persistence.py::test_same_nonce_accepted_by_exactly_one_process`
用 8 个独立进程同时验同一 nonce，断言恰好一个 `accepted`、其余 7 个
`nonce_reused`。测试日志通过 `kms.signer` / `kms.journal` logger 打印每次验签
的输入（key/version/method/nonce/时间戳/负载长度）与判定依据。
