# 显微成像原片加密数仓（单实例 API + 独立密钥服务）

显微仪器原片（raw image）的接收、流式加密存储与按号读取。每件原片使用
**独立数据密钥（DEK）**，DEK 由独立持久化的**密钥服务**用主密钥（MK）以
AES-256-GCM 信封包裹；支持主密钥在线轮换：只迁移密钥信封、**不重写图像正文**，
迁移核实完成后再销毁旧主密钥。

## 架构

```
仪器/客户端
   │  HTTP（octet-stream 流式上传 / 按号下载）
   ▼
┌──────────────────────────────┐        内部 HTTP（共享令牌）     ┌──────────────────────────┐
│ image-api (FastAPI, 单实例)   │  ────────────────────────────▶  │ keystore (FastAPI)        │
│  - 原片流式分帧加解密（内存）   │     generate/unwrap/rewrap     │  - 主密钥生命周期          │
│  - SQLite 元数据（只存密文信封）│     rotate/destroy/status      │  - DEK 包裹/解包/改包       │
│  - 轮换作业状态机 + 后台线程    │                                 │  - SQLite 持久卷（MK 本体） │
│  - blob：密文原片 .msef        │                                  └──────────────────────────┘
└──────────────┬───────────────┘                                            │
               │ 卷 api-data                    卷 keystore-data ◀──────────┘
        /data/metadata.db
        /data/blobs/*.msef（密文）
```

**安全边界**

| 资产 | 存在位置 | 不存在位置 |
|---|---|---|
| 主密钥材料 | 仅密钥服务进程内存与其持久卷 SQLite | API 进程/API 卷/日志 |
| 明文 DEK | 仅单次请求的 API 进程内存（请求结束即释放） | 任何磁盘 |
| 明文原片 | 仅请求/响应的内存流（multipart 假脱机已禁用） | 任何磁盘、任何临时文件 |
| 信封 DEK（密文） | API 的 SQLite `images.wrapped_dek` | — |
| 原片密文 | API 卷 `/data/blobs/*.msef`（AES-256-GCM 分帧） | — |

销毁主密钥 = 密钥库中密钥材料被零覆写并置 `destroyed`，密码学意义不可恢复；
对已销毁 MK 的 `unwrap/rewrap` 返回 `410 key_destroyed`。

## 快速启动

```bash
cp .env.example .env          # 修改 KEY_SERVICE_TOKEN 为强随机值
docker compose up --build
```

- API Swagger：<http://localhost:8000/docs>
- 密钥服务 Swagger：<http://localhost:8001/docs>（仅绑定 127.0.0.1）
- 健康检查：`GET /health`（两服务均有）

## 常用接口（API）

| 方法/路径 | 说明 |
|---|---|
| `POST /images` | 流式上传（随机编号）；`X-Idempotency-Token` 幂等；`X-Filename` 可选 |
| `PUT /images/{image_id}` | 按调用方编号上传 |
| `GET /images/{image_id}` | 按号下载，流式解密、逐帧 GCM 验签、SHA-256 校验 |
| `GET /images/{image_id}/meta` | 元数据/状态（不返回信封密文） |
| `GET /images` | 列表 |
| `POST /images/{image_id}/rekey` | 按编号更换该原片 DEK（202 + job_id），后台流式重加密，旧密文清除后才完成 |
| `GET /rekeys/{job_id}` | 查询换钥作业状态（staging/switching/cleaning/completed/failed） |
| `GET /images/{image_id}/rekey/latest` | 该编号最近一次换钥作业 |
| `POST /rotations` | 发起主密钥轮换（body `{"confirm": true}`），返回 202 + job_id |
| `GET /rotations/{job_id}` | 轮换进度（state/migrated/failed/progress_percent） |
| `GET /rotations/latest` | 最近一次轮换 |
| `GET /keys/status` | 代理密钥服务只读状态 |

上传请使用原始 `application/octet-stream`（`curl --data-binary @file`），
避免 multipart 带来的额外内存占用。

```bash
# 上传（按号）
curl -sS -X PUT --data-binary @slide_001.czi \
  -H 'Content-Type: application/octet-stream' \
  -H 'X-Filename: slide_001.czi' \
  http://localhost:8000/images/slide-001

# 下载并逐字节校验
curl -sS http://localhost:8000/images/slide-001 -o /tmp/slide_001.czi
sha256sum slide_001.czi /tmp/slide_001.czi

# 发起轮换 / 查进度
JOB=$(curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"confirm":true}' http://localhost:8000/rotations | python3 -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')
watch -n1 "curl -sS http://localhost:8000/rotations/$JOB"

# 按编号更换 DEK（怀疑某件原片 DEK 泄露时）
RJOB=$(curl -sS -X POST http://localhost:8000/images/slide-001/rekey \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')
watch -n1 "curl -sS http://localhost:8000/rekeys/$RJOB"
```

## 按编号换 DEK 语义（rekey，需求对照）

值班员怀疑某件已入仓原片的 DEK 泄露时，对该编号发起 `POST /images/{id}/rekey`，
作业状态持久化在 `rekey_jobs`，由后台常驻线程驱动，API 重启自动接续：

1. **取新 DEK**：向密钥服务 `generate_dek` 取一把全新 DEK（当前 MK 信封包裹），
   旧 DEK 解出的明文仅在内存中存活。
2. **流式重加密到暂存**：逐帧 GCM 验签解密旧密文，边解密边用新 DEK 重加密，
   写入同卷暂存文件 `*.msef.staging.<job>`。**明文不落盘**（无任何明文临时文件，
   自测在 blob 目录、元数据库、系统临时目录三处核查明文标记）。
3. **核对入仓摘要才切换**：解密端按入仓登记的 SHA-256 做最终核对，重加密后
   再二次比对摘要与明文尺寸；任一不符判 `failed`，绝不切换，旧版继续供数。
4. **原子切换，新旧版本不混杂**：同卷 `os.replace` 把暂存密文原子改名到规范
   路径，并以换钥前信封快照为 WHERE 条件做单行 UPDATE 切换信封/摘要。
   切换前任何下载读到的都是**完整旧版**，切换后都是**完整新版**，不存在半成品。
5. **在途下载完整**：下载打开密文前登记到在途读取计数，清理前先等其排空；
   即使超时，POSIX 已打开的旧 inode 仍可被读完。新下载只会取到完整旧版或新版。
6. **旧密文清除后才报完成**：`cleaning` 确认暂存残留消失、规范密文在位才置
   `completed`；删除受阻则留在 `cleaning` 下轮重试，不提前报完成。
7. **中断/重启接续**：崩溃在 `staging` 删暂存重做；`switching/cleaning` 按
   “图像行指针 + 文件实况”对账收敛；无主暂存文件启动时清理。
8. **与主密钥轮换交错**：轮换的 rewrap 只换信封不换 DEK。换钥切换前若发现新
   信封所绑 MK 已不是当前 MK，先 rewrap 到当前 MK 再切，**新信封始终可解包**；
   条件 UPDATE 保证**旧信封绝不覆盖轮换结果**；若该 MK 已被销毁则退回
   `staging` 重新取钥，绝不发布不可解包的信封。

换钥与轮换可并发：同件原片同时只允许一个未完成换钥（重复发起返回
`409 rekey_in_progress`）；终态后可再次换钥。

## 轮换语义（需求对照）

1. `POST /rotations` 先在密钥服务生成并切换新 MK——**新入湖立即使用新 MK**；
   本地建作业（状态持久化），未完成时再次发起返回 `409 rotation_in_progress`。
2. 后台常驻线程逐行把旧 MK 包裹的 DEK 调密钥服务 `rewrap` 改包到新 MK，
   **只更新元数据里的 64 字节信封，blob 密文正文逐字节不动**。
3. 销毁前两次零残留核验（扫描后 + 销毁前），确认没有 `ready/receiving` 行
   仍依赖旧 MK，才调用销毁；销毁后再用只读 `status` 核实，**不提前报完成**。
4. **在途下载**：下载开始时只向密钥服务解包一次 DEK，之后帧解密完全在 API
   进程内存完成；即使下载很慢、期间旧 MK 被销毁，下载仍完整成功。
5. **在途上传**：上传期间发生轮换时，finalize 会先 rewrap 改绑当前 MK 再发布；
   若旧 MK 已被销毁（极端窗口）则返回 `409 old_key_destroyed` 并判失败，
   **绝不晚发布不可读原片**。进程崩溃留下的 `receiving` 在重启时一律判失败。
6. **慢密钥服务不阻塞**：迁移在独立线程、按批让出；在线上传/下载照常完成。
7. **回执丢失**：`destroy` 网络层失败/连接被重置时，API 自动重试并以只读状态
   核实销毁是否真实生效；rewrap 带幂等令牌，重放返回同一结果。
8. **进程重启接续**：轮换作业状态在 SQLite；API 重启后自动驱动未完成作业到
   终态；若崩溃发生在“MK 已切换、作业未建”窗口，启动时自动对账补建作业。

## 故障注入（演练用，密钥服务环境变量）

| 变量 | 作用 |
|---|---|
| `KEY_OP_DELAY=0.3` | 每个密钥操作人为延迟 0.3s，模拟慢密钥服务 |
| `KEY_DESTROY_DROP_RECEIPT=true` | 销毁成功落盘后故意不回完整 HTTP 响应，模拟销毁后丢回执 |

```bash
KEY_DESTROY_DROP_RECEIPT=true docker compose up --build keystore
```

## 自测

```bash
# tests/ 下为真实 uvicorn 子进程的端到端测试（32 项，含离线加密单测）
python -m pytest tests/ -q
```

覆盖：逐字节往返（空文件/跨帧/多帧、密文布局尺寸）、信封 AAD/错钥拒绝、
明文不落盘（blob/元数据库/临时文件三处核查）、幂等上传与密钥操作幂等、
篡改 GCM 失败、完整轮换（信封迁移+正文不动+二次轮换仍不动+销毁后可读）、
进度与并发轮换拒绝、慢密钥服务并发、在途下载跨销毁、销毁丢回执自动核实、
双服务重启可读性、轮换中途重启接续、崩溃在途上传不晚发布、
跨越轮换的上传自动改绑；以及按编号换 DEK（R1–R8，见 `tests/test_rekey.py`）：
换钥后旧 DEK 解不开新密文、在途下载完整、并发下载只取完整版本、验签失败
旧版继续供数、重启/双重重启接续且无暂存残留、与主密钥轮换交错信封始终可
解包、二次换钥与并发拒绝、入口校验。

## 限制与生产化建议（见 docs/ 下说明）

单实例 + SQLite 面向单机/单节点部署；扩成多实例需把轮换协调改为分布式锁、
blob 存储换成对象存储，并在密钥服务前加 mTLS/审计与 HSM/KMS 托管根密钥。
