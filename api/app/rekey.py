"""按编号更换数据密钥（DEK）的后台作业。

触发：POST /images/{image_id}/rekey 登记作业后立即返回 202，本模块的常驻
线程把作业驱动到终态。状态全部持久化在 rekey_jobs，API 重启后自动接续。

状态机：
  staging   取新 DEK -> 流式验签解密旧密文 -> 用新 DEK 重加密到暂存文件
            （明文只在内存缓冲，不落盘；核对入仓 SHA-256 摘要）
  switching 同卷 os.replace 把暂存密文原子改名到规范路径，并以换钥前信封
            快照为 WHERE 条件做单行 UPDATE 切换信封/摘要；切换前任一时刻
            下载读到的都是完整旧版，切换后都是完整新版
  cleaning  等待在途下载排空、确认旧密文（暂存/旧 inode）清除后才报 completed
  failed    切换前失败：旧版始终完好，继续供数

与主密钥轮换的并发：
  * 轮换的 rewrap 只改信封不改 DEK；换钥的条件 UPDATE 以换钥前快照为
    WHERE 条件，绝不拿旧信封覆盖轮换后的新信封；
  * 若切换时新信封绑的主密钥已不是当前 MK，先 rewrap 到当前 MK 再切；
  * 若该 MK 已被销毁（两次轮换的极端窗口），作业退回 staging 重新取钥。
"""
from __future__ import annotations

import asyncio
import glob
import os
import threading
import time
import traceback

from .crypto_stream import IntegrityError, decrypt_stream, encrypt_stream
from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB

POLL_INTERVAL = 1.0
RETRY_BUDGET = 6
# 清理旧密文前等待在途下载排空的上限（秒）。超时后 Linux 下 unlink 仍保证
# 已打开该文件的在途下载读完（inode 引用计数），故可安全继续删除。
DRAIN_WAIT_SECONDS = float(os.environ.get("REKEY_DRAIN_SECONDS", "30"))
DRAIN_POLL = 0.2
STAGING_SUFFIX = ".staging."


class BlobReaders:
    """在途 blob 下载计数（单实例进程内）。

    下载打开密文前 enter、关闭后 exit；换钥清理旧密文前先等计数归零，
    使“换钥时已开始的下载须完整”不依赖文件系统语义即可满足。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def enter(self, path: str) -> None:
        with self._lock:
            self._counts[path] = self._counts.get(path, 0) + 1

    def exit(self, path: str) -> None:
        with self._lock:
            n = self._counts.get(path, 0) - 1
            if n <= 0:
                self._counts.pop(path, None)
            else:
                self._counts[path] = n

    def count(self, path: str) -> int:
        with self._lock:
            return self._counts.get(path, 0)

    async def wait_drained(self, path: str, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.count(path) == 0:
                return True
            await asyncio.sleep(DRAIN_POLL)
        return self.count(path) == 0


# 进程级单例：main 的下载接口与 RekeyWorker 共享
blob_readers = BlobReaders()


def staging_path(blob_dir: str, image_id: str, job_id: str) -> str:
    return os.path.join(blob_dir, f"{image_id}.msef{STAGING_SUFFIX}{job_id}")


class RekeyWorker:
    def __init__(self, db: MetadataDB, keys: KeyClient,
                 loop: asyncio.AbstractEventLoop, blob_dir: str):
        self._db = db
        self._keys = keys
        self._loop = loop
        self._blob_dir = blob_dir
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._thread_main, daemon=True,
                                        name="rekey-worker")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _thread_main(self):
        try:
            fut = asyncio.run_coroutine_threadsafe(self._run(), self._loop)
            fut.result()
        except Exception:
            traceback.print_exc()

    # ---- 启动恢复 -------------------------------------------------------
    def recover(self) -> None:
        """进程启动时对账：依据持久状态与文件实况修正各作业、清理残留。

        切换采用同卷 rename（staged -> 规范路径），配合条件 UPDATE 落库；
        任意一步崩溃都可据“图像行 blob_path + 两文件是否存在”确定唯一真相。
        """
        jobs = self._db.iter_active_rekeys()
        live_staged = {j["staged_blob_path"] for j in jobs if j["staged_blob_path"]}
        for job in jobs:
            meta = self._db.get_image(job["image_id"])
            canonical = self._canonical_path(job["image_id"])
            if job["state"] == "staging":
                # 崩溃在重加密途中：暂存密文必不完整，删除后整体重做
                self._safe_remove(job["staged_blob_path"])
                self._db.update_rekey(
                    job["job_id"], new_wrapped_dek=None,
                    new_master_key_id=None, sha256=None,
                    plain_size=None, enc_size=None, error=None)
            elif job["state"] in ("switching", "cleaning"):
                if meta is not None and meta["blob_path"] == canonical:
                    # 行已切到规范路径：切换已完成，按 cleaning 收敛
                    self._db.update_rekey(job["job_id"], state="cleaning")
                    self._safe_remove(job["staged_blob_path"])
                else:
                    # 行仍指旧密文：rename 未发生或未落库。规范路径若已被
                    # rename 占用但行未更新（极窄窗口），回滚为旧密文后重做，
                    # 保证“切换前失败仍由旧版供数”。
                    if os.path.exists(canonical) and os.path.exists(
                            job["staged_blob_path"]):
                        self._safe_remove(canonical)
                    self._db.update_rekey(
                        job["job_id"], state="staging",
                        new_wrapped_dek=None, new_master_key_id=None,
                        sha256=None, plain_size=None, enc_size=None)
        # 无主暂存文件（无对应活动作业）：删除中断残留
        for path in glob.glob(os.path.join(self._blob_dir, f"*{STAGING_SUFFIX}*")):
            if path not in live_staged:
                self._safe_remove(path)

    async def _run(self):
        while not self._stop.is_set():
            jobs = self._db.iter_active_rekeys()
            for job in jobs:
                if self._stop.is_set():
                    break
                await self._drive_job(job["job_id"])
            if not jobs:
                await asyncio.sleep(POLL_INTERVAL)
            else:
                await asyncio.sleep(0.1)

    async def _drive_job(self, job_id: str):
        retries = 0
        while not self._stop.is_set():
            job = self._db.get_rekey(job_id)
            if job is None or job["state"] in ("completed", "failed"):
                return
            try:
                if job["state"] == "staging":
                    await self._stage(job)
                    retries = 0
                elif job["state"] == "switching":
                    await self._switch(job)
                    retries = 0
                elif job["state"] == "cleaning":
                    await self._clean(job)
                    return
            except KeyServiceError as exc:
                retries += 1
                self._db.bump_rekey_retry(
                    job_id, f"key service error: {exc.code} {exc.message}")
                if retries >= RETRY_BUDGET:
                    # 达到预算后不判死：留在当前状态并重置预算，等待密钥服务
                    # 恢复或进程重启后继续；切换前失败始终不影响旧版供数。
                    retries = 0
                await asyncio.sleep(min(0.5 * (2 ** max(retries, 1)), 8.0))
            except IntegrityError as exc:
                # 旧密文验签/摘要失败：绝不切换，旧版继续供数，作业判失败
                self._discard_staging(job)
                self._db.fail_rekey(job_id, f"integrity check failed: {exc}")
                return
            except Exception as exc:  # 防御：意外错误落 failed 并留痕
                traceback.print_exc()
                self._db.fail_rekey(job_id, f"unexpected error: {exc!r}")
                return

    # ---- staging：流式解密 + 重加密 ------------------------------------
    async def _stage(self, job: dict) -> None:
        job_id, image_id = job["job_id"], job["image_id"]
        meta = self._db.get_image(image_id)
        if meta is None:
            self._db.fail_rekey(job_id, "image row disappeared")
            return
        if meta["status"] != "ready":
            self._db.fail_rekey(job_id, f"image is {meta['status']}, not ready")
            return
        if not os.path.exists(meta["blob_path"]):
            # 永久故障：旧密文已不在存储，无法重加密；旧版也无法继续供数，
            # 作业判失败并留痕，不做无意义重试。
            self._db.fail_rekey(job_id, "old encrypted blob missing on storage")
            return
        # 轮换可能已把旧 DEK 的信封改包到新 MK（DEK 本体不变）：始终以
        # 图像行当前信封解包，而不是用过时快照。
        old_dek = await self._keys.unwrap(
            meta["master_key_id"], meta["wrapped_dek"])
        dek_resp = await self._keys.generate_dek()
        new_dek = bytes.fromhex(dek_resp["dek"])
        new_wrapped = dek_resp["wrapped_dek"]
        new_mk = dek_resp["key_id"]

        staged = staging_path(self._blob_dir, image_id, job_id)
        # 重启/重跑场景：先清掉不完整暂存，再整体重写
        self._safe_remove(staged)
        writer = open(staged, "wb")
        loop = asyncio.get_running_loop()

        async def write(data: bytes):
            await loop.run_in_executor(None, writer.write, data)

        try:
            async def plain_chunks():
                # decrypt_stream 逐帧 GCM 验签，并以入仓摘要做最终核对；
                # 明文块只在内存中传递（最大 1 MiB），不产生明文临时文件。
                async for chunk in decrypt_stream(
                        _file_chunks(meta["blob_path"], loop),
                        old_dek, expected_sha256=meta["sha256"]):
                    yield chunk

            stats = await encrypt_stream(plain_chunks(), new_dek, write)
            await loop.run_in_executor(None, writer.flush)
            await loop.run_in_executor(None, os.fsync, writer.fileno())
        finally:
            await loop.run_in_executor(None, writer.close)
            del old_dek, new_dek

        # 二次核对：重加密产物的明文摘要/尺寸必须与入仓登记一致
        if meta["sha256"] and stats["sha256"] != meta["sha256"]:
            self._safe_remove(staged)
            raise IntegrityError(
                f"sha256 mismatch after re-encrypt: {stats['sha256']} "
                f"!= {meta['sha256']}")
        if meta["plain_size"] is not None and \
                stats["plain_size"] != meta["plain_size"]:
            self._safe_remove(staged)
            raise IntegrityError("plain size mismatch after re-encrypt")

        self._db.update_rekey(
            job_id,
            state="switching",
            old_master_key_id=meta["master_key_id"],
            old_wrapped_dek=meta["wrapped_dek"],
            old_blob_path=meta["blob_path"],
            new_master_key_id=new_mk,
            new_wrapped_dek=new_wrapped,
            staged_blob_path=staged,
            sha256=stats["sha256"],
            plain_size=stats["plain_size"],
            enc_size=stats["enc_size"],
            error=None)

    # ---- switching：同卷 rename + 原子条件切换 -------------------------
    def _canonical_path(self, image_id: str) -> str:
        return os.path.join(self._blob_dir, f"{image_id}.msef")

    async def _switch(self, job: dict) -> None:
        job_id, image_id = job["job_id"], job["image_id"]
        meta = self._db.get_image(image_id)
        if meta is None:
            self._db.fail_rekey(job_id, "image row disappeared")
            return
        if meta["status"] != "ready":
            self._db.fail_rekey(job_id, f"image is {meta['status']}, not ready")
            return
        canonical = self._canonical_path(image_id)
        staged = job["staged_blob_path"]

        # 幂等接续：行已切到规范路径，说明上次切换已落库，直接进入清理
        if meta["blob_path"] == canonical and not os.path.exists(staged):
            self._db.update_rekey(job_id, state="cleaning")
            return

        envelope_key = job["new_master_key_id"]
        envelope = job["new_wrapped_dek"]
        try:
            current_mk = await self._keys.current_master()
        except KeyServiceError:
            raise
        if envelope_key != current_mk:
            # 主密钥轮换同时改包：新信封先 rewrap 到当前 MK，保证仍可解包
            try:
                res = await self._keys.rewrap(
                    envelope_key, envelope, f"rekey-switch:{job_id}")
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    # 信封所绑 MK 已销毁（连续轮换极端窗口）：作废本轮产物，
                    # 退回 staging 重新取新 DEK，绝不发布不可解包的信封
                    self._discard_staging(job)
                    self._db.update_rekey(
                        job_id, state="staging", new_wrapped_dek=None,
                        new_master_key_id=None, sha256=None,
                        plain_size=None, enc_size=None)
                    return
                raise
            envelope_key, envelope = res["key_id"], res["wrapped_dek"]
            self._db.update_rekey(job_id, new_master_key_id=envelope_key,
                                  new_wrapped_dek=envelope)

        # 轮换可能在此期间 rewrap 了图像行（同 DEK 换信封）：刷新快照，
        # 条件 UPDATE 仍只写新信封，旧信封不会覆盖轮换结果。
        expect_key, expect_env = meta["master_key_id"], meta["wrapped_dek"]
        if expect_key != job["old_master_key_id"] or \
                expect_env != job["old_wrapped_dek"]:
            self._db.update_rekey(job_id, old_master_key_id=expect_key,
                                  old_wrapped_dek=expect_env)

        # 同卷原子改名：新密文落到规范路径（POSIX rename 原子替换旧文件）。
        # 已打开旧文件的在途下载仍持有原 inode，可完整读完旧版。
        if os.path.exists(staged):
            os.replace(staged, canonical)
        elif not os.path.exists(canonical):
            self._db.bump_rekey_retry(job_id, "staged blob missing before switch")
            await asyncio.sleep(POLL_INTERVAL)
            return

        ok = self._db.switch_rekey_blob(
            job_id, expect_key, expect_env, envelope_key, envelope,
            job["plain_size"], job["enc_size"], job["sha256"], canonical)
        if not ok:
            # 行被并发改动且 UPDATE 落空：新密文已在规范路径但未发布。
            # 退回 staging 由恢复逻辑重做，绝不以未知状态覆盖图像行。
            self._db.bump_rekey_retry(job_id, "switch conditional update missed")
            self._db.update_rekey(
                job_id, state="staging", new_wrapped_dek=None,
                new_master_key_id=None, sha256=None,
                plain_size=None, enc_size=None)
            return
        self._db.update_rekey(job_id, state="cleaning")

    # ---- cleaning：排空在途下载后确认旧密文已清除 ----------------------
    async def _clean(self, job: dict) -> None:
        job_id = job["job_id"]
        meta = self._db.get_image(job["image_id"])
        canonical = self._canonical_path(job["image_id"])
        if meta is None or meta["blob_path"] != canonical:
            self._db.fail_rekey(job_id, "image row diverged during cleaning")
            return
        # rename 已原子移除旧路径；这里确认没有残留暂存，并等在途旧版
        # 下载排空（rename 后旧 inode 由已打开的读者持有，读完即释放）。
        staged = job["staged_blob_path"]
        if os.path.exists(staged):
            await blob_readers.wait_drained(staged, DRAIN_WAIT_SECONDS)
            self._safe_remove(staged)
            if os.path.exists(staged):
                self._db.bump_rekey_retry(job_id, "staged blob removal pending")
                await asyncio.sleep(POLL_INTERVAL)
                return
        # 规范路径必须存在且旧暂存确认消失，才报完成
        if not os.path.exists(canonical):
            self._db.fail_rekey(job_id, "canonical blob missing at completion")
            return
        self._db.complete_rekey(job_id)

    # ---- 工具 -----------------------------------------------------------
    def _discard_staging(self, job: dict) -> None:
        """失败/回退时清理暂存密文。现役密文始终在规范路径，暂存文件
        永远不会是已发布版本，可直接删除。"""
        self._safe_remove(job.get("staged_blob_path"))

    @staticmethod
    def _safe_remove(path: str | None) -> None:
        if not path:
            return
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _file_chunks(path: str, loop: asyncio.AbstractEventLoop,
                 size: int = 1024 * 1024):
    async def gen():
        f = await loop.run_in_executor(None, open, path, "rb")
        try:
            while True:
                chunk = await loop.run_in_executor(None, f.read, size)
                if not chunk:
                    break
                yield chunk
        finally:
            await loop.run_in_executor(None, f.close)
    return gen()
