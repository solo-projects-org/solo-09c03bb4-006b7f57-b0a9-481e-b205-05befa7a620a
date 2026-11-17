"""端到端自测：真实 uvicorn 子进程跑密钥服务与 API 服务。

覆盖：
  T1  上传/按号下载，逐字节一致（含空文件、跨多帧大文件）
  T2  磁盘上只有密文（无明文落盘）、元数据库无明文 DEK
  T3  轮换：新入湖走新 MK；旧原片信封迁移、图像正文不重写；旧 MK 销毁后可读
  T4  轮换进度查询；轮换未完成拒绝新轮换
  T5  慢密钥服务（KEY_OP_DELAY）下慢下载不阻塞轮换、其他入湖取数照常
  T6  在途下载：先解包后销毁旧 MK，下载仍完整成功
  T7  销毁后丢回执（KEY_DESTROY_DROP_RECEIPT）：自动核实接续并正确报完成
  T8  两服务重启（含密钥服务重启）后已接纳原片逐字节可读
  T9  API 进程重启：未完成的在途上传判失败，不晚发布
  T10 幂等上传令牌重放
  T11 轮换中途重启 API：作业自动接续到完成
  T12 篡改密文 -> GCM 验签失败
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "api"
KEY_DIR = ROOT / "keystore"
TOKEN = "test-secret-token"


def _sweep_stray_uvicorn() -> None:
    """清理本沙箱中此前中断测试遗留的 uvicorn 子进程。

    子进程被沙箱 subreaper 收养后不会随父 pytest 退出；残留监听者会让
    _free_port 复用同一端口，请求被分发到持有不同 SQLite 的旧实例。
    仅清理命令行同时含 uvicorn 与 app.main:app 的测试服务进程。
    """
    self_pid = os.getpid()
    for attempt in range(3):
        leftovers = []
        for pdir in Path("/proc").glob("[0-9]*"):
            try:
                pid = int(pdir.name)
                if pid == self_pid:
                    continue
                cmd = (pdir / "cmdline").read_bytes().replace(b"\x00", b" ").decode()
            except (OSError, ValueError):
                continue
            if "uvicorn" in cmd and "app.main:app" in cmd:
                leftovers.append((pid, pdir))
        if not leftovers:
            return
        for pid, pdir in leftovers:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        time.sleep(0.2)


_sweep_stray_uvicorn()


def _listening_ports() -> set[int]:
    """当前命名空间内处于 LISTEN 的 TCP 端口（tcp + tcp6）。"""
    ports: set[int] = set()
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(fn).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if parts[3] != "0A":  # 0A = LISTEN
                continue
            ports.add(int(parts[1].split(":")[1], 16))
    return ports


def _free_port() -> int:
    listening = _listening_ports()
    for _ in range(50):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        # 关闭后内核可立即复用；拒绝任何已被残留监听者占用的端口
        if port not in listening:
            return port
    raise RuntimeError("could not allocate a provably free port")


def _wait_healthy(url: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"service {url} not healthy: {last}")


class Service:
    def __init__(self, name: str, app_dir: Path, port: int, env: dict):
        self.name = name
        self.proc: subprocess.Popen | None = None
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self._env = env
        self._app_dir = app_dir

    def start(self):
        env = {**os.environ, **self._env, "PYTHONPATH": str(self._app_dir)}
        # 独立进程组：stop 时向整组发信号，避免子进程被沙箱 subreaper
        # 收养后成为持旧数据库的孤儿监听者。
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "uvicorn",
             "app.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=str(self._app_dir), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
        _wait_healthy(f"{self.base}/health")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.proc.wait(timeout=5)
        out = ""
        if self.proc and self.proc.stdout:
            out = self.proc.stdout.read()
        self.proc = None
        return out

    def restart(self):
        self.stop()
        self.start()


@pytest.fixture
def stack(tmp_path):
    key_db = tmp_path / "keys"
    api_data = tmp_path / "api"
    key_db.mkdir()
    api_data.mkdir()
    kport, aport = _free_port(), _free_port()

    key_svc = Service("keystore", KEY_DIR, kport, {
        "KEYSTORE_DB": str(key_db / "keystore.db"),
        "KEY_SERVICE_TOKEN": TOKEN,
        "KEY_OP_DELAY": "0",
        "KEY_DESTROY_DROP_RECEIPT": "false",
    })
    api_svc = Service("api", API_DIR, aport, {
        "METADATA_DB": str(api_data / "metadata.db"),
        "BLOB_DIR": str(api_data / "blobs"),
        "KEY_SERVICE_URL": f"http://127.0.0.1:{kport}",
        "KEY_SERVICE_TOKEN": TOKEN,
        "UPLOAD_STALE_SECONDS": "2",
    })
    key_svc.start()
    api_svc.start()
    client = httpx.Client(base_url=api_svc.base, timeout=60)
    key_client = httpx.Client(base_url=key_svc.base, timeout=60)
    yield {
        "api": api_svc, "keys": key_svc, "client": client,
        "key_client": key_client, "data_dir": api_data,
        "blob_dir": api_data / "blobs",
    }
    client.close()
    key_client.close()
    api_svc.stop()
    key_svc.stop()


def _key_headers() -> dict:
    return {"X-Key-Service-Token": TOKEN}


def _wait_rotation(client: httpx.Client, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/rotations/{job_id}").json()
        if job["state"] in ("completed", "failed"):
            return job
        time.sleep(0.25)
    raise AssertionError("rotation did not finish")


def _upload(client: httpx.Client, data: bytes, image_id: str | None = None,
            token: str | None = None) -> httpx.Response:
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["X-Idempotency-Token"] = token
    if image_id:
        return client.put(f"/images/{image_id}", content=data, headers=headers)
    return client.post("/images", content=data, headers=headers)


def _download(client: httpx.Client, image_id: str) -> bytes:
    r = client.get(f"/images/{image_id}")
    assert r.status_code == 200, r.text
    return r.content
