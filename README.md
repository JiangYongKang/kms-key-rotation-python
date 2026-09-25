# 本地密钥轮转、签名与校验服务

在原有 FastAPI “Hello World” 服务基础上扩展的一套**完全离线**的本地密钥签名/校验能力：

- 密钥多版本与生命周期（待启用 / 启用 / 只验签 / 已吊销）；
- 轮转：新请求用当前版本签名，历史版本在过渡期内仍可验签；
- 请求签名 + 时间窗 + nonce 流水的重放防护，失败原因全部可区分；
- 私钥材料由口令派生密钥加密封存/恢复，口令错误、密文篡改、版本关系不完整均可区分；
- 状态保存在本地 JSON 文件，可离线复现；全部判定共用一把锁，轮转与验签并发时结论一致。

不依赖任何网络服务：密钥为 Ed25519，口令派生为 scrypt，加密为 AES-256-GCM。

## 运行与验证

```bash
# 运行（状态文件默认 kms_state.json，可用 LOCAL_KMS_STATE 指定）
uv sync
uv run uvicorn main:app --reload

# 测试（单测日志会打印每个判定的输入与判定依据）
uv run pytest
# 或
python3 -m pytest
```

测试覆盖：过渡期边界、重放与时间偏移、错误口令与篡改密文、版本关系不完整、
并发重复 nonce 与轮转/验签并发。日志示例：

```
INFO app.service: verify_request 输入=v404 ts=1 nonce=x method=GET path=/ body=b'' headers={} sig=...
INFO app.service: verify_request 判定=拒绝 原因=KEY_VERSION_NOT_FOUND 依据=版本 404 在本地状态中不存在
```

## 密钥状态与轮转规则

状态机（`app/keys.py`）：

```
PENDING ──activate──▶ ACTIVE ──rotate──▶ VERIFY_ONLY ──revoke──▶ REVOKED
   │                    │                    │
   └──────revoke────────┴──────revoke────────┘
REVOKED 为终态，任何复活/重复吊销都以 ILLEGAL_TRANSITION 拒绝。
```

| 状态 | 可签名 | 可验签 | 说明 |
|------|:------:|:------:|------|
| `PENDING` 待启用 | 否 | 否（`KEY_PENDING`） | 已生成未启用 |
| `ACTIVE` 启用 | 是 | 是 | 全局唯一的当前版本，`current_version` 指向它 |
| `VERIFY_ONLY` 只验签 | 否 | 过渡期内可以 | 轮转后的旧版本，`verify_until = 轮转时刻 + 过渡期` |
| `REVOKED` 已吊销 | 否 | 否（`KEY_REVOKED`） | 终态，吊销时清空 `current_version` |

轮转 `rotate(transition_seconds)` 是**原子操作**：

1. 生成新版本，置为 `ACTIVE` 并成为 `current_version`；
2. 旧 `ACTIVE` 版本置为 `VERIFY_ONLY`，过渡期截止 = 当前时间 + `transition_seconds`；
3. 两步在同一临界区内落库，不会出现“两个 ACTIVE”或“没有 ACTIVE”的中间态。

过渡期判定边界（闭区间）：`now <= verify_until` 时历史版本仍可验签；
`now > verify_until` 返回 `KEY_VERIFY_WINDOW_EXPIRED`。

## 请求签名与重放判定

签名算法：Ed25519，对**规范化请求串**签名（见 `app/signing.py`），覆盖
方法、路径、版本号、时间戳、nonce、按名排序的关键请求头，以及 body 的 SHA-256。
更换方法/路径/负载/头，或改动 version/timestamp/nonce 都会导致验签失败。

验签严格按以下顺序判定，因此每类失败都能得到唯一、可解释的原因：

| 顺序 | 检查 | 失败错误码 |
|:----:|------|-----------|
| 1 | 版本是否存在 | `KEY_VERSION_NOT_FOUND` |
| 2 | 生命周期状态 | `KEY_PENDING` / `KEY_REVOKED` / `KEY_VERIFY_WINDOW_EXPIRED` |
| 3 | 时间窗 `|now - ts| <= skew`（默认 300s） | `SKEW_TOO_OLD` / `SKEW_IN_FUTURE` |
| 4 | Ed25519 签名 | `SIGNATURE_MISMATCH` |
| 5 | nonce 流水 | `NONCE_REPLAY`（仅当前四步全部通过才写入流水） |

- nonce 由签名方生成（`secrets.token_urlsafe`），记录首次出现时间；
- 流水按 `nonce_retention_seconds`（默认 3600s）淘汰：每次判定先清除
  `first_seen <= now - retention` 的记录，长期运行内存有界；
- 只有通过全部检查才写入 nonce，因此签名错误/超时的请求不会污染流水。

## 并发一致性

`KeyService` 的所有路径共用一把可重入锁，“检查 + 状态/流水落库”在同一临界区完成。
因此同一请求（同一 nonce）被并发校验时：**恰好一次接受，其余全部 `NONCE_REPLAY`**；
轮转与验签并发时，结论集合只可能是 `{接受}` 或 `{接受, 重放}`，
不会出现“既通过又因密钥状态被拒绝”。状态文件写入采用临时文件 + `os.replace` 原子替换。

## 密钥材料封存与恢复

封套（`app/sealing.py`，JSON）结构：

```jsonc
{
  "scheme": "local-kms-seal/v1",
  "kdf": {"name": "scrypt", "n": 16384, "r": 8, "p": 1, "length": 32},
  "versions": [1, 2],                 // 版本号集合，参与 AAD 绑定
  "pw_verifier": {"salt": "...", "nonce": "...", "ciphertext": "..."},
  "payload": {"salt": "...", "nonce": "...", "ciphertext": "...", "aad": "..."}
}
```

### 口令派生参数（KDF）

- 算法：**scrypt**（`cryptography` 内置，离线）；
- 参数：`N = 16384 (2^14)`，`r = 8`，`p = 1`，输出长度 `32` 字节（AES-256）；
- salt：口令校验器与载荷各使用独立的 16 字节随机 salt；nonce 各为 12 字节随机数。
- 由口令派生两把相互独立的密钥：
  - `VE`：加密固定明文得到 `pw_verifier`，用于判断口令是否正确；
  - `KE`：加密真正的私钥材料与版本关系元数据（metadata）。
- 载荷使用 **AES-256-GCM** 认证加密，AAD 绑定 `scheme / kdf 参数 / 版本号集合`。

### 恢复时的验证方法与失败分类

恢复按以下顺序验证，任何一步失败都**不修改本地状态**（全有或全无，不泄漏半成品明文）：

1. 封套 JSON/字段完整性 → 失败 `SEAL_TAMPERED`；
2. 用口令解 `pw_verifier` → 失败 `BAD_PASSWORD`（口令错误；正确口令必通过）；
3. 用 `KE` 解载荷并校验 GCM Tag 与 AAD → 失败 `SEAL_TAMPERED`
   （密文被篡改或版本号集合/参数被改动）；
4. 载荷内版本关系一致性：
   - 私钥版本集合与元数据版本集合必须一致且非空；
   - `current_version` 必须在集合内，且与唯一的 `ACTIVE` 版本对应；
   - 不一致 → `INCOMPLETE_VERSION_SET`；
5. 指纹可复现：由私钥导出公钥，须与封存公钥一致，且
   `fingerprint = SHA-256(public_key)` 须与封存指纹一致 → 不一致 `FINGERPRINT_MISMATCH`。

全部通过后才整体替换版本集合（保留 nonce 流水，避免恢复绕过重放防护）。

## 失败原因分类总表

| 错误码 | 含义 |
|--------|------|
| `KEY_VERSION_NOT_FOUND` | 请求携带的密钥版本不存在 |
| `NO_ACTIVE_KEY` | 没有 ACTIVE 版本可用于签名 |
| `ILLEGAL_TRANSITION` | 非法状态迁移（含对 REVOKED 再次操作、并存两个 ACTIVE） |
| `KEY_PENDING` | 版本待启用，未启用不可验签 |
| `KEY_RETIRED` | 预留：非过渡期内的停用版本 |
| `KEY_REVOKED` | 版本已吊销，拒绝任何使用 |
| `KEY_VERIFY_WINDOW_EXPIRED` | 只验签过渡期已结束 |
| `SKEW_TOO_OLD` | 请求时间戳早于允许下界 |
| `SKEW_IN_FUTURE` | 请求时间戳晚于允许上界 |
| `SIGNATURE_MISMATCH` | 规范化串验签失败（方法/负载/nonce/时间戳/签名不符） |
| `NONCE_REPLAY` | nonce 已被使用，判定为重放 |
| `BAD_PASSWORD` | 封存口令错误 |
| `SEAL_TAMPERED` | 封套密文/AAD/结构被篡改或损坏 |
| `INCOMPLETE_VERSION_SET` | 恢复时版本关系不完整/不一致 |
| `FINGERPRINT_MISMATCH` | 恢复时公钥/指纹与封存不一致，不可复现 |
| `STATE_CORRUPT` | 本地状态文件损坏 |

## HTTP 接口

二进制 body 与签名在 JSON 中以 base64 传输；业务错误统一返回
`400 {"error": <错误码>, "reason": <一句话依据>}`。

| 方法/路径 | 作用 |
|-----------|------|
| `POST /keys` | 生成 PENDING 版本，返回 `{version}` |
| `POST /keys/{v}/activate` | PENDING -> ACTIVE |
| `POST /rotate?transition_seconds=86400` | 原子轮转，返回新版本号 |
| `POST /keys/{v}/transition` | 显式迁移（body: `{target, verify_until?}`） |
| `POST /keys/{v}/revoke` | 吊销版本 |
| `GET /keys` | 列出全部版本（状态/是否当前/指纹/过渡期） |
| `POST /sign` | 用当前 ACTIVE 版本签名 |
| `POST /verify` | 校验请求，返回 `{accepted, error, reason}` |
| `POST /seal/export` | body `{password}`，导出封存封套 |
| `POST /seal/restore` | body `{password, seal}`，校验并整体恢复 |

### 快速演练

```bash
curl -s -XPOST localhost:8000/keys
# {"version":1}
curl -s -XPOST localhost:8000/keys/1/activate
curl -s -XPOST 'localhost:8000/rotate?transition_seconds=3600'
curl -s localhost:8000/keys
```

## 代码结构

| 文件 | 职责 |
|------|------|
| `app/errors.py` | 失败原因枚举与业务异常 |
| `app/keys.py` | 生命周期状态、状态机迁移表、公钥指纹 |
| `app/signing.py` | 请求规范化与 Ed25519 签名/验签 |
| `app/sealing.py` | scrypt 口令派生与 AES-GCM 封存/恢复 |
| `app/state.py` | 本地 JSON 状态持久化与 nonce 淘汰 |
| `app/service.py` | 编排：生命周期、签名验签顺序判定、并发锁、封存恢复校验 |
| `main.py` | FastAPI HTTP 入口 |
| `tests/` | 生命周期/边界、重放与时间窗、封存恢复、并发、HTTP 测试 |
