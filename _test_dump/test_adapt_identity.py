"""
target 身份（内核串 / 指纹）归属于哪台机器 —— 回归测试。

背景：适配向导解析「另一台机器的 ROM」时，target 的 kernel 与 fingerprint
曾经取「装进工具那一刻连着的设备」，导致 pick_payload 把这份 so 错配给
一台没适配过的机器（错配的偏移会让漏洞链在内核里随机位置崩）。

跑法：python -m pytest _test_dump/test_adapt_identity.py -q
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import adapter

DEV_KERNEL = "4.19.157-perf-g77c132eccfab-dirty"      # 手上这台 Leaf5
DEV_FP = "ONYX/TabBoox/TabBoox:13/TKQ1.230615.001/GV2.027.SQ83A:user/release-keys"
IMG_BANNER = ("4.19.157-perf-ge2582afab8ec-dirty (onyx@onyxUbuntu) #11 SMP "
              "PREEMPT Sat May 30 11:56:07 CST 2026")   # Tab8 的 ROM


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    """把 targets_root() 指到临时目录，别碰用户真实的适配仓库。"""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    root = tmp_path / "Leaf5RootTool" / "targets"
    root.mkdir(parents=True)
    return root


def _so(tmp_path, name="preload.so"):
    p = tmp_path / name
    p.write_bytes(b"\x7fELF" + bytes(64))
    return str(p)


# ---------------- pick_identity：镜像说了算 ----------------

def test_pick_identity_prefers_image_banner():
    k, fp = adapter.pick_identity(
        IMG_BANNER, {"kernel": DEV_KERNEL, "fingerprint": DEV_FP})
    assert k == "4.19.157-perf-ge2582afab8ec-dirty", "内核串必须来自镜像 banner"
    assert fp == "", "镜像不是这台机器的，指纹不能继承"


def test_pick_identity_inherits_fingerprint_when_same_kernel():
    k, fp = adapter.pick_identity(
        "4.19.157-perf-g77c132eccfab-dirty (onyx@x) #38 SMP",
        {"kernel": DEV_KERNEL, "fingerprint": DEV_FP})
    assert k == DEV_KERNEL and fp == DEV_FP


def test_pick_identity_without_banner_uses_device():
    assert adapter.pick_identity(None, {"kernel": DEV_KERNEL,
                                        "fingerprint": DEV_FP}) == (DEV_KERNEL, DEV_FP)


def test_pick_identity_no_device():
    assert adapter.pick_identity(IMG_BANNER, {}) == \
        ("4.19.157-perf-ge2582afab8ec-dirty", "")


def test_pick_identity_explicit_args_win():
    assert adapter.pick_identity(IMG_BANNER, {"kernel": DEV_KERNEL, "fingerprint": DEV_FP},
                                 kernel="4.19.157-hand", fingerprint="FP-HAND") == \
        ("4.19.157-hand", "FP-HAND")


# ---------------- install_target：不能让设备串盖掉镜像串 ----------------

def test_install_rewrites_kernel_from_image(repo, tmp_path):
    """解析 Tab8 的 ROM、install 时连着 Leaf5 —— manifest 必须记 Tab8。"""
    tid = "migr-tab8"
    tdir = repo / tid
    tdir.mkdir()
    # gen 阶段留下的符号指纹（带镜像 banner 解析出来的 kernel_version）
    (tdir / "symfp.json").write_text(json.dumps({
        "sym_digest": "abc123",
        "kernel_version": "4.19.157-perf-ge2582afab8ec-dirty",
        "kernel_commit": "e2582afab8ec",
        "kernel_build": 11,
    }), encoding="utf-8")

    adapter.install_target(tid, _so(tmp_path),
                           {"kernel": DEV_KERNEL, "fingerprint": DEV_FP})

    m = json.loads((tdir / "manifest.json").read_text(encoding="utf-8"))
    assert m["kernel"] == "4.19.157-perf-ge2582afab8ec-dirty"
    assert m["dev_kernel"] == DEV_KERNEL, "install 时连着的那台要留档，便于排查"
    assert "fingerprint" not in m, "镜像不是这台机器的，指纹必须撤掉"
    assert m["dev_fingerprint"] == DEV_FP
    assert m["sym_digest"] == "abc123", "符号指纹照旧并进来"


def test_install_keeps_identity_when_same_kernel(repo, tmp_path):
    """镜像就是这台机器 —— 一个字段都不许动。"""
    tid = "migr-same"
    tdir = repo / tid
    tdir.mkdir()
    (tdir / "symfp.json").write_text(json.dumps({
        "sym_digest": "d", "kernel_version": DEV_KERNEL}), encoding="utf-8")

    adapter.install_target(tid, _so(tmp_path),
                           {"kernel": DEV_KERNEL, "fingerprint": DEV_FP})

    m = json.loads((tdir / "manifest.json").read_text(encoding="utf-8"))
    assert m["kernel"] == DEV_KERNEL
    assert m["fingerprint"] == DEV_FP
    assert "dev_kernel" not in m and "dev_fingerprint" not in m


def test_install_without_symfp_keeps_device(repo, tmp_path):
    """从 kallsyms 文本生成的 target 没有 banner，只能信设备。"""
    tid = "migr-nobanner"
    (repo / tid).mkdir()

    adapter.install_target(tid, _so(tmp_path),
                           {"kernel": DEV_KERNEL, "fingerprint": DEV_FP})

    m = json.loads((repo / tid / "manifest.json").read_text(encoding="utf-8"))
    assert m["kernel"] == DEV_KERNEL and m["fingerprint"] == DEV_FP


# ---------------- pick_payload：第三档要认 kernel_version ----------------

def _target(repo, tid, meta):
    d = repo / tid
    d.mkdir()
    (d / "preload.so").write_bytes(b"\x7fELF" + bytes(64))
    (d / "manifest.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def test_pick_matches_kernel_version(repo):
    """老 manifest 的 kernel 记错了，但 kernel_version 对 —— 仍要能命中。"""
    d = _target(repo, "old-tab8", {
        "kernel": DEV_KERNEL,                      # 被设备串污染的老数据
        "kernel_version": "4.19.157-perf-ge2582afab8ec-dirty",
    })
    so, meta = adapter.pick_payload(dev_kernel="4.19.157-perf-ge2582afab8ec-dirty")
    assert so == os.path.join(str(d), "preload.so")
    assert meta["kernel_version"] == "4.19.157-perf-ge2582afab8ec-dirty"


def test_pick_does_not_match_other_kernel(repo):
    _target(repo, "tab8", {"kernel": "4.19.157-perf-ge2582afab8ec-dirty"})
    so, meta = adapter.pick_payload(dev_kernel=DEV_KERNEL)
    assert so is None and meta is None


def test_pick_fingerprint_second_tier(repo):
    d = _target(repo, "leaf5", {"fingerprint": DEV_FP, "kernel": DEV_KERNEL})
    so, _ = adapter.pick_payload(dev_fingerprint=DEV_FP)
    assert so == os.path.join(str(d), "preload.so")


def test_pick_sym_digest_first_tier(repo):
    """符号指纹最可信：命中了就不看后面两档。"""
    d = _target(repo, "by-digest", {"sym_digest": "zzz",
                                    "fingerprint": "别的机器", "kernel": "别的内核"})
    so, meta = adapter.pick_payload(dev_fingerprint=DEV_FP, dev_kernel=DEV_KERNEL,
                                    sym_digest="zzz")
    assert so == os.path.join(str(d), "preload.so") and meta["sym_digest"] == "zzz"
