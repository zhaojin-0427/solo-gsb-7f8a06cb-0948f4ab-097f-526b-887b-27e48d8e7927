# Webhook 本地验签 API（Python / FastAPI / SQLite）

一个只监听 `localhost` 的 Webhook 签名校验服务：接收调用方报告的请求要素，
按固定规则重放**规范化字符串**，用共享密钥计算 HMAC-SHA256 并恒定时间比对，
同时做时间戳窗口与 nonce 防重放检查。另提供按流（stream）写入有序事件的
接口：乱序事件先暂存，只有从 1 起连续的事件才开放读取；在开放事件之上还提供
**带租约的可恢复顺序消费接口**（claim / ack），同一条事件在确认前只会被一个
消费者领取，租约超时后可凭新令牌重新领取，重启后租约与消费进度仍然有效。
已确认的事件前缀还可以**按流清理（compact）**：删除前缀事件并持久化一个只增
不减的清理界限，读取到已清理区间时返回 `410` 指引客户端从界限处续读。每条已
开放事件还串有一条 **SHA-256 完整性摘要链**：乱序暂存不生成摘要，缺口补齐、
序号开放时按序把前一摘要与事件 `[stream_id, sequence, data]` 数组的紧凑
JSON 拼接求摘要；可通过 `GET /streams/{id}/integrity` 在单个 SQLite 快照内
重算校验。

- 框架：FastAPI + Uvicorn
- 存储：SQLite（WAL 模式，原子登记 nonce，事件与水位单事务推进，租约、已确认
  序号、清理界限与完整性摘要落库保存，重启后数据仍然有效；旧版数据库首次启动
  时自动补建摘要链，并把关停前写下的**旧对象编码**摘要链先核验、再迁移为数组
  编码，不丢失事件、nonce、租约与消费进度）
- 一条命令启动，默认地址 <http://localhost:8000>，交互式文档 <http://localhost:8000/docs>

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

服务即运行在 <http://localhost:8000>，端口仅绑定到宿主机回环地址
（Compose 中为 `127.0.0.1:8000:8000`），不会暴露到其他网络接口。
容器内置了一个**仅用于本地开发**的默认
密钥 `dev-only-secret-change-me`，nonce、事件、水位、完整性摘要、租约、已确认
序号与清理界限数据库保存在命名卷 `nonce-data` 中（挂载到 `/app/data`），容器
重启不会丢失已使用的 nonce、事件、未到期的租约、消费进度、完整性链与清理界限。

使用自己的密钥（推荐）：

```bash
WEBHOOK_SECRET=$(openssl rand -hex 32) docker compose up --build
```

或在项目根目录放置 `.env` 文件（参考 `.env.example`）：

```
WEBHOOK_SECRET=一个足够长的随机字符串
```

> Compose 默认文件会自动读取同目录的 `.env`；无需任何额外参数。

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

## 验签规则

规范化字符串由以下 **6 行**用 `\n` 拼接而成（无结尾换行）：

```text
<方法>
<路径>
<规范查询串>
<正文 SHA-256 小写十六进制摘要>
<Unix 时间戳>
<nonce>
```

1. **方法**：`method` 转大写（如 `post` → `POST`）。
2. **路径**：`path` 原样使用（如 `/webhook`）。
3. **规范查询串**：
   - 每个键、每个值先做 UTF-8 百分号编码；仅 ASCII 字母数字与 `-._~` 不编码
     （RFC 3986 unreserved 集合，十六进制数字大写，如空格 → `%20`）；
   - 对编码后的 `(键, 值)` 依次按键、按值做字典序排序；
   - **保留重复键**（每个重复项各占一对）；
   - 用 `&` 连接成 `k=v` 形式；无查询参数时为空行。
4. **正文摘要**：`body` 的 **UTF-8 字节**的 SHA-256 小写十六进制摘要（64 字符）。
5. **时间戳**：Unix 秒级整数，必须在服务器当前时间的 **±300 秒**内。
6. **nonce**：一次性随机值。

签名为上述规范化字符串的 HMAC-SHA256，输出**小写十六进制**（64 字符），
密钥来自环境变量 `WEBHOOK_SECRET`。服务端使用 `hmac.compare_digest` 恒定时间比对，
且要求签名严格为小写十六进制（大写或非法字符直接判为签名错误）。

## 处理顺序与失败语义

对每个请求严格按以下顺序处理，三种失败互不混淆：

| 顺序 | 检查 | 失败响应 | 是否占用 nonce |
| --- | --- | --- | --- |
| 1 | 时间戳是否在 ±300 秒窗口内 | `401 timestamp_out_of_window` | 否 |
| 2 | HMAC 签名是否匹配（恒定时间） | `401 invalid_signature` | 否 |
| 3 | nonce 是否首次出现（原子 `INSERT`） | `409 replayed_nonce` | 已是第二次提交 |

只有前两步全部通过后才执行 `INSERT OR IGNORE` 登记 nonce；
**签名错误、时间超窗、请求格式错误都不会占用 nonce**，客户端修正后可用同一 nonce 重试。
同一 nonce 第一次成功之后再出现即为重放（即使时间戳仍在窗口内）。

## API

### `POST /verify`

请求体（JSON）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `method` | string | HTTP 方法，服务端转大写 |
| `path` | string | 请求路径，如 `/webhook` |
| `query` | `[{key, value}, ...]` | 查询键值对列表；重复键 = 重复元素 |
| `body` | string | 原始正文字符串；按 UTF-8 字节求摘要（默认空串） |
| `timestamp` | integer | Unix 秒级时间戳 |
| `nonce` | string | 一次性随机值（非空） |
| `signature` | string | 小写十六进制 HMAC-SHA256（64 字符） |

成功：

```json
{ "ok": true, "reason": "verified", "nonce": "5f4c…" }
```

失败（HTTPException 的 `detail` 字段）：

```json
{ "ok": false, "error": "invalid_signature", "detail": "…" }
{ "ok": false, "error": "timestamp_out_of_window", "detail": "…" }
{ "ok": false, "error": "replayed_nonce", "detail": "…" }
```

| `error` | HTTP 状态码 | 含义 |
| --- | --- | --- |
| `timestamp_out_of_window` | 401 | 时间戳超出服务器时间 ±300 秒 |
| `invalid_signature` | 401 | 签名不匹配，或不是小写 64 位十六进制 |
| `replayed_nonce` | 409 | nonce 已成功使用过 |

请求体缺少必填字段或类型错误时，FastAPI 返回标准 `422` 校验错误。

## 有序事件流

在验签之上提供两个端点，用于把签名后的事件按 **stream（流）+ sequence（序号）**
可靠地投递并按序读取。

### 水位与乱序语义

- 每条流维护一个**水位（watermark）**：从序号 `1` 起连续无缺号的最大序号。
- 事件按 `(stream_id, sequence)` 存入 SQLite。序号大于「水位 + 1」的事件
  **先暂存**，暂存中的事件不可读取。
- 当缺号被补齐时，水位一次性推进过其后所有已暂存的连续事件，响应的
  `opened` 列出**本次提交新开放**的序号；乱序暂存提交的 `opened` 为空数组。
- 同一 `(stream_id, sequence)` 重复提交返回 `409 duplicate_sequence`
  （即使旧事件还在暂存中）。
- nonce 在 `/verify` 与 `/streams/events` 之间**全局共享**。
- nonce 登记、事件写入、水位更新在**同一个 `BEGIN IMMEDIATE` 事务**内完成；
  并发补号只有一个提交成功，不会重复开放事件。
- **验签失败、时间超窗、事件 body 格式错误、序号冲突均不占用 nonce**，
  修正后可用同一 nonce 重试。

### `POST /streams/events`

请求外层与 `POST /verify` **完全一致**（同字段、同签名规则）：
被签名的 `path` 为 `/streams/events`、`method` 通常为 `POST`，而签名覆盖的
`body` 字符串本身必须是一个 **JSON 对象**：

```json
{
  "stream_id": "orders-42",
  "sequence": 1,
  "data": { "any": "合法 JSON 值，对象/数组/数字/字符串/null 均可" }
}
```

| 字段 | 要求 |
| --- | --- |
| `stream_id` | 非空字符串 |
| `sequence` | 从 1 起的整数（`0`、负数、`1.0`、`true`、字符串均拒绝） |
| `data` | 必带，值为任意 JSON 类型 |

成功响应：

```json
{
  "ok": true,
  "stream_id": "orders-42",
  "sequence": 3,
  "watermark": 3,
  "opened": [1, 2, 3]
}
```

| 失败 `error` | HTTP 状态码 | 含义 | 是否占用 nonce |
| --- | --- | --- | --- |
| `timestamp_out_of_window` | 401 | 时间戳超出 ±300 秒 | 否 |
| `invalid_signature` | 401 | 签名不匹配 | 否 |
| `invalid_event_body` | 400 | 签名 body 不是合法事件 JSON（缺字段/类型错） | 否 |
| `replayed_nonce` | 409 | nonce 已被使用（全局） | 已是第二次提交 |
| `duplicate_sequence` | 409 | 该流已有相同序号 | 否（事务回滚） |

### 乱序暂存与补号示例

```python
import hashlib, hmac, json, time, urllib.request, urllib.error, uuid
from app.signing import build_canonical_string

secret = b"dev-only-secret-change-me"
BASE = "http://localhost:8000"

def send_event(stream_id, sequence, data, nonce=None):
    # 1) 事件对象 -> 紧凑 JSON 字符串，这就是被签名的 body
    body = json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        separators=(",", ":"),
    )
    envelope = {
        "method": "POST",
        "path": "/streams/events",
        "query": [],
        "body": body,
        "timestamp": int(time.time()),
        "nonce": nonce or uuid.uuid4().hex,
    }
    canonical = build_canonical_string(
        envelope["method"], envelope["path"], [],
        envelope["body"], envelope["timestamp"], envelope["nonce"],
    )
    envelope["signature"] = hmac.new(
        secret, canonical.encode(), hashlib.sha256
    ).hexdigest()

    req = urllib.request.Request(
        f"{BASE}/streams/events",
        data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())

# 3 先到：缺 1、2，事件暂存，不开放任何序号
send_event("orders-42", 3, {"event": "shipped"})
# -> 200 {"sequence": 3, "watermark": 0, "opened": []}

# 2 到达：仍然缺 1，继续暂存
send_event("orders-42", 2, {"event": "paid"})
# -> 200 {"sequence": 2, "watermark": 0, "opened": []}

# 1 到达补齐缺号：1、2、3 在一次水位推进中同时开放
send_event("orders-42", 1, {"event": "created"})
# -> 200 {"sequence": 1, "watermark": 3, "opened": [1, 2, 3]}

# 重复序号冲突，且不占用本次 nonce
send_event("orders-42", 2, {"event": "paid-again"})
# -> 409 {"error": "duplicate_sequence", ...}
```

### `GET /streams/{stream_id}/ready?after_seq=n`

按序号升序返回水位内、且序号 **大于** 非负整数 `n` 的已开放事件；
**读取不删除**，可重复拉取，也可把上次看到的最大序号作为 `after_seq`
做增量轮询。未知流或窗口为空时返回 `watermark: 0` 与空数组；
`after_seq` 为负或非整数返回 `422`。

当该流已经[清理过前缀](#post-streamsstream_idcompact)、而 `after_seq`
**小于清理界限 `compacted_until`** 时，对应事件已被物理删除，服务返回
**`410 Gone`**，响应体在 `detail` 中给出当前界限，客户端应以
`after_seq=compacted_until` 续读：

```json
{
  "detail": {
    "ok": false,
    "error": "already_compacted",
    "detail": "stream 'orders-42' has compacted away every sequence up to 3; resume reading with after_seq=3",
    "compacted_until": 3
  }
}
```

`after_seq` **等于或大于**界限时查询行为完全照旧（见下文
[清理后续读示例](#清理后继续读取示例)）。

```bash
curl -s 'http://localhost:8000/streams/orders-42/ready?after_seq=0'
```

```json
{
  "stream_id": "orders-42",
  "watermark": 3,
  "events": [
    {"sequence": 1, "data": {"event": "created"}},
    {"sequence": 2, "data": {"event": "paid"}},
    {"sequence": 3, "data": {"event": "shipped"}}
  ]
}
```

只拉增量（`after_seq=2`）时，`events` 中只剩序号 3；重复 GET 返回不变。

## 可恢复的顺序消费（claim / ack）

开放事件除了可被 `GET .../ready` 只读轮询外，还可以**领取—确认**地顺序消费，
保证同一条事件在确认前不会被分发给两个消费者，且消费者崩溃后可恢复：

- 每条流额外维护一个**已确认序号 `confirmed_seq`**：从 `0` 起，只有当前领取的
  事件被确认后才向前推进。
- `POST /streams/{stream_id}/claim` 只领取**该流已确认序号的下一条**
  （`confirmed_seq + 1`），且**绝不越过现有水位**：暂存在缺口之后的事件不可
  领取；没有可领事件时返回 **`204 No Content`**。
- 领取时在 SQLite 中写入一个 **30 秒租约**：随机 `token` 与到期 Unix 秒
  `expires_at`，响应返回 `sequence`、`data`、`token`、`expires_at`。
- 租约**未到期**时再次领取返回 **`409 lease_active`**；租约**到期后**可重新领取
  **同一条**事件，并换发一个**新的随机令牌**（旧令牌立即失效）。
- `POST /streams/{stream_id}/ack` 接收 JSON `{"token": "..."}`，只允许
  **尚未到期的当前租约**确认。成功后在**同一个 `BEGIN IMMEDIATE` 事务**内原子
  推进该流的已确认序号并清除租约。
- 旧令牌 / 错误令牌、重复确认、租约到期后的确认一律返回 **`409`** 且**不推进**
  已确认序号（错误码分别为 `invalid_token` / `no_active_lease` /
  `lease_expired`）。
- 领取与确认在 SQLite 中以 `BEGIN IMMEDIATE` **串行化**，并发调用只有一个
  胜出；租约和已确认序号都持久化在数据库里，**进程重启后仍然有效**。
- claim / ack **不验签、不消耗 nonce**（它们是消费端的本地投递原语；事件写入
  仍走带签名的 `/streams/events`），也不影响 `GET .../ready` 的只读语义。

### 领取与确认示例

```bash
# 没有可领事件（未知流 / 缺口未补齐 / 已全部确认）-> 204，无响应体
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  http://localhost:8000/streams/orders-42/claim
# 204

# 领取已确认序号的下一条（这里是序号 1）
curl -s -X POST http://localhost:8000/streams/orders-42/claim
```

```json
{
  "stream_id": "orders-42",
  "sequence": 1,
  "data": {"event": "created"},
  "token": "6a59f5d0b1542934556628af807c0d7c5927ef18",
  "expires_at": 1727000030
}
```

```bash
# 租约未到期，再次领取 -> 409 lease_active
curl -s -X POST http://localhost:8000/streams/orders-42/claim
# {"detail":{"ok":false,"error":"lease_active","detail":"…"}}

# 用领取时拿到的令牌确认；成功后已确认序号原子推进到 1、租约被清除
curl -s -X POST http://localhost:8000/streams/orders-42/ack \
  -H 'Content-Type: application/json' \
  -d '{"token":"6a59f5d0b1542934556628af807c0d7c5927ef18"}'
```

```json
{ "ok": true, "stream_id": "orders-42", "sequence": 1, "confirmed_seq": 1 }
```

```bash
# 重复确认 / 旧令牌 -> 409，且不推进
curl -s -X POST http://localhost:8000/streams/orders-42/ack \
  -H 'Content-Type: application/json' \
  -d '{"token":"6a59f5d0b1542934556628af807c0d7c5927ef18"}'
# {"detail":{"ok":false,"error":"no_active_lease","detail":"…"}}
```

### 超时重领示例

消费者领取后若 30 秒内没有确认（例如进程崩溃），租约到期：到期后、尚未被
重新领取前拿旧令牌来确认会得到 `409 lease_expired`；随后同一条事件可被
**重新领取并换发新令牌**，旧令牌立即变为 `invalid_token`：

```bash
# 假设上一次领取返回 token = aaa…（30 秒内未 ack）
sleep 31

# 到期后、重新领取前，拿旧令牌确认 -> 409 lease_expired，已确认序号不动
curl -s -X POST http://localhost:8000/streams/orders-42/ack \
  -H 'Content-Type: application/json' -d '{"token":"aaa…旧令牌…"}'
# {"detail":{"ok":false,"error":"lease_expired","detail":"…"}}

# 重新领取：仍是同一条（sequence 不变），但 token 换成 bbb…
curl -s -X POST http://localhost:8000/streams/orders-42/claim
# {"sequence":1,"data":{"event":"created"},
#  "token":"bbb…新令牌…","expires_at":1727000061}

# 重新领取后旧令牌立即失效 -> 409 invalid_token，已确认序号仍不动
curl -s -X POST http://localhost:8000/streams/orders-42/ack \
  -H 'Content-Type: application/json' -d '{"token":"aaa…旧令牌…"}'
# {"detail":{"ok":false,"error":"invalid_token","detail":"…"}}

# 用新令牌确认成功，序号 1 才被标记为已确认
curl -s -X POST http://localhost:8000/streams/orders-42/ack \
  -H 'Content-Type: application/json' -d '{"token":"bbb…新令牌…"}'
# {"ok":true,"stream_id":"orders-42","sequence":1,"confirmed_seq":1}

# 已确认序号到达水位后再领取 -> 204
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  http://localhost:8000/streams/orders-42/claim
# 204
```

| 端点 | 状态码 | `error`（在 `detail.error`） | 含义 |
| --- | --- | --- | --- |
| `POST /streams/{id}/claim` | 200 | — | 领取成功，返回序号 / data / token / 到期时间 |
| | 204 | — | 没有越过水位且未确认的可领事件 |
| | 409 | `lease_active` | 下一条事件已有未到期租约 |
| `POST /streams/{id}/ack` | 200 | — | 确认成功，已确认序号原子推进 |
| | 409 | `no_active_lease` | 该流当前没有租约（未领取或已确认，重复确认） |
| | 409 | `invalid_token` | 令牌与当前租约不符（旧令牌 / 错误令牌） |
| | 409 | `lease_expired` | 租约已到期，确认不推进 |

请求体缺少 `token` 或为空字符串时返回标准 `422` 校验错误。

## 按流清理已确认前缀（compact）

事件被 claim / ack 顺序确认之后，可以删除已经确认的事件前缀以回收空间；
清理**以流为单位**，并持久化一个只增不减的**清理界限**：

- `POST /streams/{stream_id}/compact`，JSON 请求体只含一个**非负整数**
  `through_seq`（`0`、负数以外的数字、`1.0`、`true`、字符串都会被 `422`
  拒绝）。
- 只允许清理**不超过该流 `confirmed_seq`** 的前缀：`through_seq >
  confirmed_seq` 时返回 **`409 compact_ahead_of_confirmed`**，不删除任何事件。
  未知流的 `confirmed_seq` 视为 `0`，因此**未知流只允许 `through_seq: 0`**
  （成功、幂等，且不会落任何状态）。
- 界限 `compacted_until` 持久化在 SQLite 中且**只能递增**：请求的
  `through_seq` 不高于旧界限时直接成功并返回旧界限（**幂等**）。
- 界限推进与「删除该流 `sequence <= 界限` 的事件」在**同一个
  `BEGIN IMMEDIATE` 写事务**内完成，并与事件写入、领取、确认**串行化**；
  任何读取在单个只读事务快照内完成，不会读到「界限已推进但事件还没删完」的
  中间状态。
- 清理后水位（watermark）与已确认进度（confirmed_seq）**都不回退**；
  claim 仍从 `confirmed_seq + 1` 继续，不受前缀删除影响。
- **已被清理的序号仍然拒绝重复写入**：再次签名提交 `sequence <=
  compacted_until` 的事件返回 `409 duplicate_sequence`，且同样**不占用
  nonce**（回滚后该 nonce 可用于新序号）。
- compact 与 claim / ack 一样**不验签、不消耗 nonce**，属于消费端本地原语。

成功响应返回当前界限与确认进度：

```json
{
  "ok": true,
  "stream_id": "orders-42",
  "compacted_until": 3,
  "confirmed_seq": 3
}
```

越过确认进度时（`detail.compacted_until` 附带当前界限，便于客户端回退）：

```json
{
  "detail": {
    "ok": false,
    "error": "compact_ahead_of_confirmed",
    "detail": "cannot compact stream 'orders-42' through sequence 4: only 3 sequence(s) have been confirmed; acknowledge more events first",
    "compacted_until": 0
  }
}
```

| 端点 | 状态码 | `error`（在 `detail.error`） | 含义 |
| --- | --- | --- | --- |
| `POST /streams/{id}/compact` | 200 | — | 界限推进成功，或请求不高于旧界限（幂等）；返回 `compacted_until` / `confirmed_seq` |
| | 409 | `compact_ahead_of_confirmed` | `through_seq` 超过该流已确认序号（未知流即超过 0），未删除任何事件 |
| `GET /streams/{id}/ready` | 410 | `already_compacted` | `after_seq < compacted_until`，前缀已删除；`detail.compacted_until` 给出续读界限 |

### 清理及继续读取示例

接着前面的 claim / ack：假设序号 1–3 已依次确认（`confirmed_seq = 3`），
序号 4、5 已开放但尚未确认。

```bash
# 未确认的前缀不能清理：through_seq=4 > confirmed_seq=3 -> 409，什么都不删
curl -s -X POST http://localhost:8000/streams/orders-42/compact \
  -H 'Content-Type: application/json' -d '{"through_seq":4}'
# {"detail":{"ok":false,"error":"compact_ahead_of_confirmed",
#   "detail":"cannot compact stream 'orders-42' through sequence 4: ...",
#   "compacted_until":0}}

# 清理已确认的 1..3；界限与删除在同一个写事务中完成
curl -s -X POST http://localhost:8000/streams/orders-42/compact \
  -H 'Content-Type: application/json' -d '{"through_seq":3}'
# {"ok":true,"stream_id":"orders-42","compacted_until":3,"confirmed_seq":3}

# 不高于旧界限的请求幂等：界限仍是 3，不报错
curl -s -X POST http://localhost:8000/streams/orders-42/compact \
  -H 'Content-Type: application/json' -d '{"through_seq":0}'
# {"ok":true,"stream_id":"orders-42","compacted_until":3,"confirmed_seq":3}
```

继续读取：`after_seq` 小于界限 `3` 时得到 `410` 并附上界限；把
`after_seq` 设为返回的 `compacted_until` 即可无缝续读，之后的轮询、
claim / ack 行为与清理前完全一致。

```bash
# 旧的轮询位置落在已删除区间 -> 410 并给出界限
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:8000/streams/orders-42/ready?after_seq=0'
# 410
curl -s 'http://localhost:8000/streams/orders-42/ready?after_seq=0'
# {"detail":{"ok":false,"error":"already_compacted",
#   "detail":"...resume reading with after_seq=3","compacted_until":3}}

# 从界限处续读：事件 4、5 照常返回（watermark 不回退）
curl -s 'http://localhost:8000/streams/orders-42/ready?after_seq=3'
# {"stream_id":"orders-42","watermark":5,
#  "events":[{"sequence":4,"data":{...}},{"sequence":5,"data":{...}}]}

# claim 也从 confirmed_seq+1（=4）继续，就像没有清理过一样
curl -s -X POST http://localhost:8000/streams/orders-42/claim
# {"stream_id":"orders-42","sequence":4,"data":{...},"token":"…","expires_at":…}
```

客户端可以把「轮询位置」按下面的规则保存：`200` 时取返回事件的最大序号
（没有事件则保持原值）；`410` 时把轮询位置**向前快进**到
`detail.compacted_until`，随后立即重试。

## 完整性摘要链（integrity）

每条流对**已开放**（处于从 `1` 起连续前缀内）的事件维护一条 SHA-256 摘要链，
用于发现事件体被篡改、事件行丢失或摘要损坏：

- **乱序暂存的事件不生成摘要**：落在缺口之后的事件只是暂存，链不延伸。
- 缺口补齐、若干序号在一次水位推进中开放时，按序号从小到大依次计算
  `摘要(n) = SHA-256( 前一摘要原始 32 字节 ‖ 事件数组的 UTF-8 紧凑 JSON )`，
  与事件写入、水位推进在**同一个 `BEGIN IMMEDIATE` 事务**内落库；链首
  （序号 1，或清理界限之后的第一条）使用 **32 个零字节**作为前一摘要。
- 被拼接的事件 JSON 固定为**三元素数组 `[stream_id, sequence, data]`**
  （数组顺序即字段含义，顶层不序列化键名），紧凑格式、无多余空白；
  `data` 内部**嵌套对象的键排序**，非 ASCII 字符按 UTF-8 直接编码。摘要
  以原始 32 字节保存，接口以小写十六进制（64 字符）返回。
- **compact 原子保留界限处摘要作为锚点**：删除前缀事件时只删除
  `sequence < 新界限` 的摘要，`sequence = 界限` 的摘要保留为链锚点
  （界限为 `0` 时不删除任何摘要）；界限之后的新事件与所有校验都从该锚点
  续接，即使锚点对应的事件本身已被删除。
- **校验只覆盖保留区间**：已清理（compact）流的前缀事件已被物理删除，
  `/integrity` 能且只能校验 `(compacted_until, watermark]` 这段保留区间；
  已删除前缀的完整性不在校验范围内（详见下文
  [已清理流的校验边界](#已清理流的校验边界)）。
- **旧数据库自动升级**：升级到本特性后的服务首次启动时，为尚无摘要链的
  旧库按现有清理界限补建摘要链；对仍保存**旧对象编码**（把事件序列化为
  `{"stream_id","sequence","data"}` 对象求摘要）摘要链的数据库，在
  **单个写事务**内先核验旧链、再把全部摘要迁移为数组编码并写入格式标记，
  与并发的事件提交按事务串行
  （详见下文[启动时的格式迁移](#启动时的格式迁移)）。事件、租约、已确认
  序号与清理界限均原样保留。

### 摘要计算示例

以流 `orders-42` 的前两条事件为例（`‖` 表示字节拼接，左侧为原始字节）：

```text
事件 1 的数组紧凑 JSON：
  ["orders-42",1,{"event":"created"}]
摘要(1) = SHA-256( 00…00（32 个零字节）‖ 上面的 UTF-8 字节 )
        = 1635bd502d871c55201ebedf69c5e7e8b53f54f117900dc21df97c6bafafc1d6

事件 2 的数组紧凑 JSON：
  ["orders-42",2,{"event":"paid"}]
摘要(2) = SHA-256( 摘要(1) 原始 32 字节 ‖ 上面的 UTF-8 字节 )
        = 5849953bcdf1e68cdddb450ec3d50cb097951d0a943af25bd52e15eabfe07d98
```

嵌套对象的键在序列化时排序，例如 `data` 为 `{"z":1,"a":[1,2],"中":"文"}`
的第三条事件，其拼接字节为
`["orders-42",3,{"a":[1,2],"z":1,"中":"文"}]` 的 UTF-8 编码
（`中`、`文` 直接以 UTF-8 字节出现，不转义），算得
`摘要(3) = d0282a309098b736a1a28e5986b5965fa532033c0181f198d6e481ccf0ce3abe`。
用任何语言按同一规则（数组、紧凑、嵌套键排序、UTF-8）都能复算出相同摘要。

### 已清理流的校验边界

清理（compact）会物理删除 `sequence <= compacted_until` 的事件，因此摘要链
对**已删除前缀无法重算**：`/integrity` 从界限处保留的锚点摘要出发，只逐条
重算 `(compacted_until, watermark]` 区间内的保留事件。响应中的
`compacted_until` 就是该校验边界——**界限及之前的事件不在校验覆盖范围内**，
调用方不应把空链尾或校验通过解读为对已删除前缀的任何保证。

对于在旧版本库上完成启动迁移的已清理流（见下节），界限处的锚点被显式重置为
**32 个零字节**：新链自界限之后的第一条保留事件重新开始，校验覆盖范围同样是
`(compacted_until, watermark]`。

### 启动时的格式迁移

摘要链的事件编码曾把事件序列化为 `{"stream_id","sequence","data"}` **对象**
求摘要；现行约定为 `[stream_id, sequence, data]` **数组**。数据库在
`app_meta` 表的 `digest_format` 键记录链编码（`array-v2` 为数组编码），
服务每次启动时按下述规则处理：

1. **识别**：没有 `digest_format` 标记（或标记为 `object-v1`）且已存在摘要
   链的数据库，即为旧对象编码，需要迁移。
2. **核验与重建同在单个写事务**：迁移在**单个 `BEGIN IMMEDIATE` 写事务**
   内完成全部工作——先取得写锁，再在事务内重新读取格式标记、流清单、
   水位与清理界限，按旧的对象编码对每条流的保留链逐条核验（已清理流从
   界限处保留的旧锚点出发，只核验保留区间），全部通过后立即重算所有
   摘要并写入 `digest_format = array-v2` 标记。未清理流从序号 1 起以零
   摘要为首项重算；已清理流在清理界限写入**零摘要新锚点**，再从界限
   之后的第一条保留事件起重算。
3. **并发边界**：写锁自核验之前即持有，并发的事件提交与迁移**按事务
   串行**——在迁移取锁**之前**已提交的开放事件出现在迁移的快照内，被
   一并核验并**纳入重建**（此类提交由现行写入路径产生，其新链接为数组
   编码、接在库存旧链尾之后；核验恰好接受这种「对象前缀＋数组后缀、
   编码至多切换一次」的形状，重建会把整条链规范化为纯数组编码）；在
   迁移持锁**期间**到达的写入会阻塞至迁移提交，随后接在已迁移的链尾
   之后正常延伸。两种时序下都不会出现「事件已开放却没有摘要」的窗口，
   只读查询（WAL 快照）不被迁移阻塞。若另一个服务实例同时启动，只有
   一个执行迁移，其余在事务内读到已提交的 `array-v2` 标记后直接跳过。
4. **损坏不静默重写**：任一旧链核验失败（链接或事件缺失、摘要与两种
   编码均不符、锚点行畸形），服务以 `ChainCorruptionError`
   **拒绝启动**，所有摘要与标记保持原样，由运维介入（修复数据后重启即可
   正常迁移）。
5. **可安全重试**：摘要与标记在同一事务提交，迁移中途崩溃不会留下半成品，
   下次启动重新核验并完整重试；迁移只触碰摘要表与标记行，**事件、nonce、
   租约、水位与已确认进度不丢失**。已带 `array-v2` 标记的库启动时完全跳过
   迁移（幂等）。

### `GET /streams/{stream_id}/integrity`

在**同一个 SQLite 只读快照**内，从清理锚点（界限处保留的摘要；界限为 `0`
或界限被迁移重置时为 32 个零字节）出发，对界限之上到水位为止的事件逐条重算
SHA-256 链接并与库里保存的摘要比对。**未知流返回空链**（界限与水位为 `0`、
链尾为 64 个 `0`、无异常序号）；只有暂存事件（水位仍为 `0`）的流同样返回
空链。

```bash
curl -s http://localhost:8000/streams/orders-42/integrity
```

成功（保留区间内全部校验通过）：

```json
{
  "stream_id": "orders-42",
  "compacted_until": 3,
  "watermark": 5,
  "tail_digest": "9f1c4a7e0b3d…（64 个小写十六进制字符）",
  "first_invalid_sequence": null
}
```

| 字段 | 说明 |
| --- | --- |
| `compacted_until` | 重算起点的清理界限（校验边界）；其保留摘要即链锚点，界限为 `0` 或被迁移重置时锚点为 32 个零字节 |
| `watermark` | 当前水位（参与重算的最后一个序号） |
| `tail_digest` | 已校验链尾（最后一个校验通过序号的重算摘要）；未知流 / 链尚未开始时为 64 个 `0` |
| `first_invalid_sequence` | **首个缺失事件或摘要不符的序号**；全部通过（含未知流）时为 `null` |

发现问题时校验在首个异常序号处停止，`tail_digest` 停留在其前一条已验证摘要
（即从该摘要起续算即可定位差异）。下面的例子先演示乱序暂存不产生摘要，再
演示补齐与 compact 后的续接：

```bash
# 序号 2 先到（缺 1）：暂存，链尚未开始
curl -s http://localhost:8000/streams/orders-42/integrity
# {"stream_id":"orders-42","compacted_until":0,"watermark":0,
#  "tail_digest":"0000…0000","first_invalid_sequence":null}

# 序号 1 补齐后（事件经 POST /streams/events 签名投递），1、2 同时开放：
# 链尾变为 digest(1 -> 2)，没有异常序号
curl -s http://localhost:8000/streams/orders-42/integrity
# {"stream_id":"orders-42","compacted_until":0,"watermark":2,
#  "tail_digest":"ab12…","first_invalid_sequence":null}

# 确认 1、2 并 compact 到 2 后：摘要 2 作为锚点保留，校验从锚点续接
curl -s -X POST http://localhost:8000/streams/orders-42/compact \
  -H 'Content-Type: application/json' -d '{"through_seq":2}'
# {"ok":true,"stream_id":"orders-42","compacted_until":2,"confirmed_seq":2}
curl -s http://localhost:8000/streams/orders-42/integrity
# {"stream_id":"orders-42","compacted_until":2,"watermark":2,
#  "tail_digest":"ab12…（仍是序号 2 的锚点摘要）","first_invalid_sequence":null}

# 未知流：空链
curl -s http://localhost:8000/streams/unknown/integrity
# {"stream_id":"unknown","compacted_until":0,"watermark":0,
#  "tail_digest":"0000…0000","first_invalid_sequence":null}
```

该端点与 `ready` 一样为只读查询，不验签、不消耗 nonce，也不会修改任何摘要。

## 调用示例

### Python（标准库即可生成签名，与服务端同一套代码）

```python
import hashlib, hmac, json, time, uuid
from app.signing import build_canonical_string

secret = b"dev-only-secret-change-me"   # 与服务端 WEBHOOK_SECRET 一致
payload = {
    "method": "post",                    # 会被转大写
    "path": "/webhook",
    "query": [
        {"key": "source", "value": "github"},
        {"key": "tag", "value": "v1.0"},
        {"key": "tag", "value": "release"},   # 重复键
    ],
    "body": json.dumps({"event": "ping"}, separators=(",", ":")),
    "timestamp": int(time.time()),
    "nonce": uuid.uuid4().hex,
}
canonical = build_canonical_string(
    method=payload["method"].upper(),
    path=payload["path"],
    query_items=[(q["key"], q["value"]) for q in payload["query"]],
    body=payload["body"],
    timestamp=payload["timestamp"],
    nonce=payload["nonce"],
)
payload["signature"] = hmac.new(
    secret, canonical.encode("utf-8"), hashlib.sha256
).hexdigest()

# POST /verify，Content-Type: application/json，body 为 json.dumps(payload)
```

### 一键演示脚本

仓库自带纯标准库客户端（签名 + 发送），默认请求正在运行的本地服务：

```bash
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_client.py
```

用固定 nonce 连跑两次即可看到第二次返回 `409 replayed_nonce`：

```bash
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_client.py --nonce abc123
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_client.py --nonce abc123
```

乱序事件流（先投 3、2，再补 1，随后演示重复序号与 nonce 复用）：

```bash
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_streams.py
```

领取 / 确认 / 超时重领（默认快速演示一轮 claim→409→正确/错误 ack；加
`--wait-expiry` 会真实等待 31 秒，展示租约到期后同一条事件换发新令牌重新投递）：

```bash
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_claims.py
WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_claims.py --wait-expiry
```

### curl

签名依赖当前时间戳（±300 秒有效），建议先用上面的 Python 片段生成最新的
`timestamp` 与 `signature`，再填入：

```bash
curl -s -X POST http://localhost:8000/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "POST",
    "path": "/webhook",
    "query": [{"key":"source","value":"github"}],
    "body": "{\"event\":\"ping\"}",
    "timestamp": 1727000000,
    "nonce": "replace-with-unique-random-value",
    "signature": "replace-with-lowercase-hex-hmac"
  }'
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WEBHOOK_SECRET` | 无（容器 Compose 提供开发默认值） | HMAC 共享密钥；**必须设置**，未设置时服务拒绝启动 |
| `NONCE_DB_PATH` | `data/nonces.db`（容器内 `/app/data/nonces.db`） | SQLite 数据库路径；nonce、流事件、水位、完整性摘要、租约与清理界限都存放在该库 |

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export WEBHOOK_SECRET=dev-only-secret-change-me
uvicorn app.main:app --reload --port 8000
```

运行测试：

```bash
pytest
```

不依赖任何第三方库的核心逻辑自检（可在未安装 FastAPI 的环境运行）：

```bash
python3 scripts/selfcheck.py
```

## 项目结构

```text
app/
  __init__.py
  signing.py   # 百分号编码、规范化字符串、HMAC 计算与恒定时间比对（纯标准库）
  events.py    # 签名 body 字符串解析为 {stream_id, sequence, data} 事件
  integrity.py # 事件数组紧凑 JSON 规范化与 SHA-256 摘要链接（含旧对象编码的核验用实现，纯标准库）
  db.py        # SQLite：nonce 原子登记、事件暂存、水位推进、摘要链与启动格式迁移、租约领取/确认、前缀清理
  main.py      # FastAPI：/verify、/streams/events、/ready、/integrity、/claim、/ack、/compact、/health
tests/         # pytest 单元与端到端测试（TestClient，含并发补号、并发领取/确认、旧库升级与对象编码链迁移）
scripts/
  example_client.py    # 签名并调用 /verify 的演示客户端
  example_streams.py   # 乱序暂存 / 补号 / 重复序号的流演示客户端
  example_claims.py    # 领取 / 确认 / 超时换令牌重领的消费演示客户端
  selfcheck.py         # 纯标准库核心逻辑自检（含摘要链、旧库升级与格式迁移）
Dockerfile
docker-compose.yml  # 端口仅绑定 127.0.0.1:8000
requirements.txt / requirements-dev.txt
.env.example
```
