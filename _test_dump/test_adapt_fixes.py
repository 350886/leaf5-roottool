# -*- coding: utf-8 -*-
"""V1 适配链修复的回归用例。

覆盖 2026-11-02 这一轮改的五处：
  1. install 自动找到 gen 写在「仓库」里的 symfp.json（以前只找应用目录，
     结果 manifest 少了 sym_digest，match 第一档永远命中不了）
  2. install 时没给 --kernel 就用镜像内核串填上（以前留下空字符串）
  3. write_sym_fp 在无 banner 时也记 kernel_version
  4. fp.match 在「候选没记符号指纹」时不再说「符号序列不同」
  5. fp.match 在地址被 kptr 隐藏时不再说「先 root」

跑：python -m pytest _test_dump/test_adapt_fixes.py -q
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import adapter          # noqa: E402
import fp as fpmod      # noqa: E402


SODIGEST = "6e567200bbb33dc1389869001be942757a50b164a87d9550c812ac86eb7e3ea2"
KVER = "4.19.157-perf-g77c132eccfab-dirty"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """把 %LOCALAPPDATA% 指到临时目录，别碰真机上的 target 仓库。"""
    la = tmp_path / "la"
    la.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(la))
    return tmp_path


@pytest.fixture()
def repo(tmp_path):
    """造一个最小的仓库：exploit/targets/<id>/{target.h,symfp.json}"""
    d = tmp_path / "repo" / "exploit" / "targets" / "t1"
    d.mkdir(parents=True)
    (d / "target.h").write_text("#define X 1\n", encoding="utf-8")
    (d / "symfp.json").write_text(json.dumps({
        "sym_digest": SODIGEST, "sym_count": 121921,
        "kernel_version": KVER,
    }), encoding="utf-8")
    return tmp_path / "repo"


def _so(tmp_path, payload=b"\x7fELF" + bytes(64)):
    p = tmp_path / "preload.so"
    p.write_bytes(payload)
    return str(p)


# ---------------- 1. install 从仓库带上 symfp ----------------

def test_install_picks_symfp_from_repo(env, repo, tmp_path):
    d = adapter.install_target("t1", _so(tmp_path), {}, repo=str(repo))
    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert m["sym_digest"] == SODIGEST, "仓库里的 symfp.json 必须被并进 manifest"
    assert m["sym_count"] == 121921
    assert m["symfp_from"].endswith("symfp.json")


def test_install_prefers_explicit_symfp(env, repo, tmp_path):
    """--symfp 给了就以它为准，别被自动探测覆盖。"""
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"sym_digest": "deadbeef"}), encoding="utf-8")
    d = adapter.install_target("t1", _so(tmp_path), {}, symfp=str(other))
    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert m["sym_digest"] == "deadbeef"


def test_install_without_any_symfp_still_works(env, tmp_path):
    """没有 symfp 也要能装（外部编好的 so 就是这种情况）。"""
    d = adapter.install_target("bare", _so(tmp_path), {})
    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert "sym_digest" not in m
    assert m["so_md5"]


# ---------------- 2. kernel 收口 ----------------

def test_install_fills_kernel_from_symfp(env, repo, tmp_path):
    """install 没给 --kernel：用 gen 记下的镜像内核串，而不是留空。"""
    d = adapter.install_target("t1", _so(tmp_path), {}, repo=str(repo))
    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert m["kernel"] == KVER


def test_install_image_kernel_wins_over_device(env, repo, tmp_path):
    """给了设备串但与镜像串不同：镜像说了算，设备串留档到 dev_kernel。"""
    dev = "4.19.157-perf-gaaaaaaaaaaaa-dirty"
    d = adapter.install_target("t1", _so(tmp_path), {"kernel": dev},
                               repo=str(repo))
    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    assert m["kernel"] == KVER
    assert m["dev_kernel"] == dev


# ---------------- 3. write_sym_fp 记 kernel ----------------

def test_write_sym_fp_keeps_kernel_without_banner(tmp_path):
    syms = tmp_path / "syms.txt"
    syms.write_text("ffffffa017480000 T _text\n"
                    "ffffffa017481000 T foo\n", encoding="utf-8")
    tdir = tmp_path / "targets" / "x"
    p = adapter.write_sym_fp(str(syms), str(tdir), None, kernel=KVER)
    assert p and os.path.isfile(p)
    meta = json.load(open(p, encoding="utf-8"))
    assert meta["kernel_version"] == KVER


# ---------------- 4/5. match 的措辞 ----------------

def _fp(digest="", ver=KVER, zeroed=0, syms=121921):
    return {"kernel_ver": ver, "sym": {"sym_digest": digest,
                                       "kernel_syms": syms,
                                       "zeroed": zeroed}}


def test_match_same_build_by_digest():
    r = fpmod.match(_fp(digest=SODIGEST), [{"id": "t1", "sym_digest": SODIGEST}])
    assert r["verdict"] == "same_build" and r["id"] == "t1"


def test_match_says_missing_digest_not_different():
    """候选没记 symbol 指纹时，不能把「没记」说成「序列不同」。"""
    r = fpmod.match(_fp(digest=SODIGEST),
                    [{"id": "old", "kernel": KVER}])
    assert r["verdict"] == "same_version"
    assert "没记符号指纹" in r["why"]
    assert "符号序列不同" not in r["why"]


def test_match_says_different_when_digests_exist():
    r = fpmod.match(_fp(digest=SODIGEST),
                    [{"id": "t2", "kernel": KVER, "sym_digest": "0" * 64}])
    assert r["verdict"] == "same_version"
    assert "符号序列不同" in r["why"]


def test_match_hidden_addresses_not_reported_as_no_root():
    """地址被 kptr 隐藏时，建议应该是「放开 kptr」，不是「先 root」。"""
    r = fpmod.match(_fp(zeroed=121921), [])
    assert r["verdict"] == "no_target"
    assert "kptr_restrict" in r["advice"]
    assert "先把设备 root 起来" not in r["advice"]


def test_match_no_target_when_addresses_visible():
    r = fpmod.match(_fp(zeroed=0), [])
    assert "先把设备 root 起来" in r["advice"]
