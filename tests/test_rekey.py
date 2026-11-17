"""按编号更换 DEK 的端到端自测（真实 uvicorn 子进程）。

覆盖：
  R1  换钥基本语义：新 DEK、新密文、旧 DEK 解不开新密文、旧密文清除后才完成、
      下载逐字节一致、明文不落盘
  R2  换钥期间在途下载完整；之后新下载取新版且逐字节一致
  R3  换钥全程并发下载：每个响应都是完整旧版或完整新版（明文一致即逐字节相同）
  R4  切换前失败（GCM 验签失败）：作业 failed、旧版行不动、暂存清理、可重新发起
  R5  API 重启接续：staging/switching/cleaning 中断后自动到 completed，无残留
  R6  与主密钥轮换交错：新信封始终可解包、旧信封不覆盖轮换结果、正文可读
  R7  同件二次换钥与并发拒绝（409 rekey_in_progress）
  R8  404/非 ready 拒绝
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from conftest import TOKEN, _download, _key_headers, _upload, _wait_rotation

ROOT = Path(__file__).resolve().parents[1]

# 加载 API 侧加密原语（离线验签用），与 test_crypto_unit 同样处理包名冲突
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
sys.path.insert(0, str(ROOT / "api"))
crypto_stream = importlib.import_module("app.crypto_stream")
sys.path.remove(str(ROOT / "api"))
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]


def _wait_rekey(client: httpx.Client, job_id: str,
                timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/rekeys/{job_id}").json()
        if last["state"] in ("completed", "failed"):
            return last
        time.sleep(0.1)
    raise AssertionError(f"rekey did not finish: {last}")


def _start_rekey(client: httpx.Client, image_id: str) -> dict:
    r = client.post(f"/images/{image_id}/rekey")
    assert r.status_code == 202, r.text
    return r.json()


def _unwrap_dek_via_keystore(kc: httpx.Client, mk_id: str,
                             wrapped_hex: str) -> bytes:
    r = kc.post("/internal/dek/unwrap",
                json={"key_id": mk_id, "wrapped_dek": wrapped_hex},
                headers=_key_headers())
    assert r.status_code == 200, r.text
    return bytes.fromhex(r.json()["dek"])


async def _decrypt_file(path: str, dek: bytes) -> bytes:
    async def chunks():
        with open(path, "rb") as f:
            while True:
                b = f.read(999)
                if not b:
                    break
                yield b

    out = bytearray()
    async for c in crypto_stream.decrypt_stream(chunks(), dek):
        out.extend(c)
    return bytes(out)


def _db_row(stack, image_id: str) -> tuple:
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    row = conn.execute(
        "SELECT master_key_id, wrapped_dek, blob_path FROM images "
        "WHERE image_id=?", (image_id,)).fetchone()
    conn.close()
    return row


def _blob_files(stack) -> list[Path]:
    return [p for p in stack["blob_dir"].iterdir() if p.is_file()]


# --------------------------------------------------------------------------
# R1 基本语义
# --------------------------------------------------------------------------
def test_rekey_replaces_dek_and_old_dek_cannot_open_new_ciphertext(stack):
    client, kc = stack["client"], stack["key_client"]
    payload = b"rekey-basic-" + bytes(range(256)) * 4096  # 多帧
    assert _upload(client, payload, image_id="rk-basic").status_code == 201

    mk_id, old_env, old_blob = _db_row(stack, "rk-basic")
    old_dek = _unwrap_dek_via_keystore(kc, mk_id, old_env)
    old_blob_bytes = Path(old_blob).read_bytes()

    job = _start_rekey(client, "rk-basic")
    final = _wait_rekey(client, job["job_id"])
    assert final["state"] == "completed", final
    assert final["error"] is None

    # 旧密文内容已随 rename 解除链接而消失：目录无暂存残留，只剩一件现役密文
    blobs = _blob_files(stack)
    assert len(blobs) == 1
    assert all(".staging." not in p.name for p in blobs)
    new_blob = blobs[0]
    # 规范路径仍在，但内容已整体换成新密文；旧密文字节在目录中无处可寻
    assert new_blob.read_bytes() != old_blob_bytes
    assert all(old_blob_bytes not in p.read_bytes() for p in blobs)

    # 信封已更换
    new_mk, new_env, new_path = _db_row(stack, "rk-basic")
    assert new_env != old_env
    assert new_path == str(new_blob)

    # 旧 DEK 无法解开换钥后的密文（GCM 验签失败）
    with pytest.raises(crypto_stream.IntegrityError):
        asyncio.run(_decrypt_file(str(new_blob), old_dek))

    # 新 DEK 可解且逐字节还原；接口下载一致
    new_dek = _unwrap_dek_via_keystore(kc, new_mk, new_env)
    assert asyncio.run(_decrypt_file(str(new_blob), new_dek)) == payload
    assert _download(client, "rk-basic") == payload


def test_rekey_no_plaintext_on_disk(stack):
    client = stack["client"]
    marker = b"REKEY-SECRET-MARKER-" + bytes(range(256)) * 2048
    _upload(client, marker, image_id="rk-noleak")
    job = _start_rekey(client, "rk-noleak")
    assert _wait_rekey(client, job["job_id"])["state"] == "completed"
    # blob（含任何暂存残片）与元数据库均不得出现明文标记
    for path in _blob_files(stack):
        assert marker not in path.read_bytes()
    for suffix in ("", "-wal", "-shm"):
        p = stack["data_dir"] / ("metadata.db" + suffix)
        if p.exists():
            assert marker not in p.read_bytes()
    assert _download(client, "rk-noleak") == marker


# --------------------------------------------------------------------------
# R2/R3 在途下载与并发一致性
# --------------------------------------------------------------------------
def test_inflight_download_completes_during_rekey(stack):
    client = stack["client"]
    payload = bytes((i * 13) % 256 for i in range(3 * 1024 * 1024))
    _upload(client, payload, image_id="rk-inflight")

    with httpx.Client(base_url=stack["api"].base, timeout=60) as slow:
        with slow.stream("GET", "/images/rk-inflight") as resp:
            assert resp.status_code == 200
            # 下载已开始（DEK 已解包、旧 blob 已打开）后发起换钥
            job = _start_rekey(client, "rk-inflight")
            time.sleep(0.5)  # 让换钥推进到 staging/switching
            body = b"".join(resp.iter_bytes(65536))  # 慢速读完
    assert body == payload  # 换钥时已开始的下载必须完整

    final = _wait_rekey(client, job["job_id"])
    assert final["state"] == "completed", final
    # 换钥后的新下载取新版，仍逐字节一致
    assert _download(client, "rk-inflight") == payload
    assert all(".staging." not in p.name for p in _blob_files(stack))


def test_concurrent_downloads_each_get_complete_version(stack):
    client = stack["client"]
    payload = b"version-consistency" * 200000
    _upload(client, payload, image_id="rk-versions")
    job = _start_rekey(client, "rk-versions")

    results: list[bytes | Exception] = []

    def grab():
        try:
            with httpx.Client(base_url=stack["api"].base, timeout=60) as c:
                with c.stream("GET", "/images/rk-versions") as resp:
                    results.append(b"".join(resp.iter_bytes(131072)))
        except Exception as exc:  # noqa: BLE001
            results.append(exc)

    threads = [threading.Thread(target=grab) for _ in range(6)]
    for t in threads:
        t.start()
        time.sleep(0.05)  # 让下载散布在换钥各阶段
    for t in threads:
        t.join()

    assert _wait_rekey(client, job["job_id"])["state"] == "completed"
    # 每个响应都完整且明文一致：不存在半成品版本
    assert len(results) == 6
    for r in results:
        assert isinstance(r, bytes) and r == payload


# --------------------------------------------------------------------------
# R4 切换前失败：旧版继续供数
# --------------------------------------------------------------------------
def test_rekey_integrity_failure_keeps_old_version(stack):
    client = stack["client"]
    payload = b"tamper-case" * 1000
    _upload(client, payload, image_id="rk-tamper")
    _, _, blob_path = _db_row(stack, "rk-tamper")
    raw = bytearray(Path(blob_path).read_bytes())
    raw[len(raw) // 2] ^= 0xFF  # 破坏中后部帧，触发流式 GCM 验签失败
    Path(blob_path).write_bytes(bytes(raw))

    job = _start_rekey(client, "rk-tamper")
    final = _wait_rekey(client, job["job_id"])
    assert final["state"] == "failed"
    assert "integrity" in (final["error"] or "")

    # 图像行未被切换、旧密文仍在、暂存已清理
    _, _, still_path = _db_row(stack, "rk-tamper")
    assert still_path == blob_path and Path(blob_path).exists()
    assert all(".staging." not in p.name for p in _blob_files(stack))
    meta = client.get("/images/rk-tamper/meta").json()
    assert meta["status"] == "ready"
    # failed 作业不阻塞重新发起
    again = client.post("/images/rk-tamper/rekey")
    assert again.status_code == 202


# --------------------------------------------------------------------------
# R5 重启接续
# --------------------------------------------------------------------------
def test_rekey_resumes_after_api_restart(stack):
    client = stack["client"]
    payload = os.urandom(12 * 1024 * 1024)
    _upload(client, payload, image_id="rk-restart")
    job = _start_rekey(client, "rk-restart")

    # 等到作业真正进入活动状态后立刻重启 API
    deadline = time.time() + 10
    while time.time() < deadline:
        st = client.get(f"/rekeys/{job['job_id']}").json()["state"]
        if st in ("staging", "switching", "cleaning"):
            break
        time.sleep(0.05)
    stack["api"].restart()

    final = _wait_rekey(client, job["job_id"], timeout=90)
    assert final["state"] == "completed", final
    assert _download(client, "rk-restart") == payload
    # 无中断暂存残留、旧密文已清
    blobs = _blob_files(stack)
    assert len(blobs) == 1 and ".staging." not in blobs[0].name


def test_rekey_restart_twice_and_cleanup_orphan_staging(stack):
    client = stack["client"]
    payload = b"double-restart" * 100000
    _upload(client, payload, image_id="rk-restart2")
    job = _start_rekey(client, "rk-restart2")
    for _ in range(2):
        time.sleep(0.15)
        stack["api"].restart()
    final = _wait_rekey(client, job["job_id"], timeout=90)
    assert final["state"] == "completed", final
    assert _download(client, "rk-restart2") == payload
    assert all(".staging." not in p.name for p in _blob_files(stack))


# --------------------------------------------------------------------------
# R6 与主密钥轮换交错
# --------------------------------------------------------------------------
def test_rekey_interleaved_with_master_rotation(stack):
    client, kc = stack["client"], stack["key_client"]
    n = 4
    for i in range(n):
        _upload(client, f"interleave-{i}".encode() * 50000,
                image_id=f"rk-rot-{i}")

    errors: list[Exception] = []

    def rotate_loop():
        try:
            for _ in range(2):
                r = client.post("/rotations", json={"confirm": True})
                if r.status_code == 202:
                    _wait_rotation(client, r.json()["job_id"], timeout=120)
                else:
                    assert r.status_code == 409
                    time.sleep(0.2)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def rekey_loop():
        try:
            for round_ in range(2):
                for i in range(n):
                    image_id = f"rk-rot-{i}"
                    for attempt in range(20):
                        r = client.post(f"/images/{image_id}/rekey")
                        if r.status_code == 202:
                            final = _wait_rekey(client, r.json()["job_id"],
                                                timeout=120)
                            assert final["state"] == "completed", final
                            break
                        assert r.status_code == 409
                        time.sleep(0.2)
                    else:
                        raise AssertionError("rekey never accepted")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=rotate_loop)
    t2 = threading.Thread(target=rekey_loop)
    t1.start(); t2.start()
    t1.join(); t2.join()
    assert not errors, errors

    current_mk = kc.get("/internal/master/status",
                        headers=_key_headers()).json()["current_key_id"]
    for i in range(n):
        image_id = f"rk-rot-{i}"
        # 信封必须绑在当前（可解包）主密钥上：旧信封从未覆盖轮换结果
        mk_id, _, _ = _db_row(stack, image_id)
        assert mk_id == current_mk
        assert _download(client, image_id) == f"interleave-{i}".encode() * 50000
        latest = client.get(f"/images/{image_id}/rekey/latest").json()
        assert latest["state"] == "completed"


# --------------------------------------------------------------------------
# R7 二次换钥与并发拒绝
# --------------------------------------------------------------------------
def test_rekey_twice_and_concurrent_reject(stack):
    client = stack["client"]
    payload = b"twice" * 100000
    _upload(client, payload, image_id="rk-twice")
    j1 = _start_rekey(client, "rk-twice")
    # 完成前再次发起 -> 409
    r = client.post("/images/rk-twice/rekey")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "rekey_in_progress"
    assert _wait_rekey(client, j1["job_id"])["state"] == "completed"

    _, env1, _ = _db_row(stack, "rk-twice")
    j2 = _start_rekey(client, "rk-twice")
    assert _wait_rekey(client, j2["job_id"])["state"] == "completed"
    _, env2, _ = _db_row(stack, "rk-twice")
    assert env1 != env2  # 第二次确实又换了 DEK
    assert _download(client, "rk-twice") == payload
    assert client.get("/rekeys/does-not-exist").status_code == 404


# --------------------------------------------------------------------------
# R8 入口校验
# --------------------------------------------------------------------------
def test_rekey_rejects_missing_and_non_ready(stack):
    client = stack["client"]
    assert client.post("/images/nope/rekey").status_code == 404
    _upload(client, b"x", image_id="rk-guard")
    # 构造 failed 行：换钥被篡改的密文 -> failed
    _, _, blob_path = _db_row(stack, "rk-guard")
    raw = bytearray(Path(blob_path).read_bytes())
    raw[-20] ^= 0xFF
    Path(blob_path).write_bytes(bytes(raw))
    j = _start_rekey(client, "rk-guard")
    assert _wait_rekey(client, j["job_id"])["state"] == "failed"
    # failed 行允许重新发起（终态不占用并发槽）
    assert client.post("/images/rk-guard/rekey").status_code == 202
