#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在内存镜像里找 C3RB3R 会话主密钥（48 字节）/ brute-force the wrapped-key footer.

原理
----
每个文件的 ChaCha8 密钥被 AES-256-CBC 包在页脚开头 48 字节：

    rec   = file_key(32) | nonce(8) | nonce(8)          # nonce 写了两遍
    footer[0:48] = AES-256-CBC_encrypt(rec, key=master[16:48], iv=master[0:16])

会话主密钥 = IV(16) | AES key(32) 共 48 字节，只存在于加密进程内存里。
于是给定任意候选 32 字节 k，无需 IV 就能做 64 位校验：

    T  = footer[16:24] XOR footer[24:32]          (LE 读)
    P3 = AES256_decrypt_block(k, footer[32:48])
    ((P3 >> 64) ^ (P3 & 2^64-1)) == T   →  k 正确

13.5e9 个候选的期望误报数约 7e-10，实际等于无误报。命中后再用 IV 做一次
完整 CBC 解密复核。

为什么一定要先跑 --selftest
---------------------------
"扫不到"本身没有信息量：可能是真的没有，也可能是扫法错了、路径写错了、
文件被截断了。--selftest 合成一个已知主密钥埋进随机数据，用**同一段代码**
扫一遍并要求精确命中，这样「没找到」才有分量。

用法
----
    python3 scan_master.py --sample /volume1/x.db.L0CK3D \\
        --sources memdump.lime zram0.img ... zram5.img \\
        --stride 1 --workers 20

    python3 scan_master.py --selftest          # 先跑这个

    python3 scan_master.py --sample x.L0CK3D --selftest-only
"""
import argparse
import glob
import os
import random
import struct
import sys
import tempfile
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FOOT = 588
PRINTABLE = bytes(range(32, 127))


# ---------------------------------------------------------------- 页脚与目标

def load_sample(path):
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size < FOOT:
            sys.exit("%s 小于 %d 字节，不是加密文件" % (path, FOOT))
        f.seek(-FOOT, os.SEEK_END)
        footer = f.read(FOOT)
    if len(footer) != FOOT:
        sys.exit("读页脚失败：%s" % path)
    mode, pct, cm, _ = footer[572:576]
    if cm == 0x21:
        sys.exit("该文件页脚 crypto=0x21（诱饵材料），即使拿到密钥也解不开，换样本")
    if cm != 0x20:
        sys.exit("未知 crypto 模式 0x%02x" % cm)
    osz = struct.unpack_from("<Q", footer, 580)[0]
    if osz + FOOT != size:
        print("警告：原始大小 %d + 588 ≠ 文件大小 %d，页脚可能不是这条文件的"
              % (osz, size), file=sys.stderr)
    C2, C3 = footer[16:32], footer[32:48]
    T = (int.from_bytes(C2[0:8], "little") ^ int.from_bytes(C2[8:16], "little"))
    info = {"path": path, "marker": footer[568:572].hex(),
            "mode": "0x%02x" % mode, "pct": pct, "osz": osz}
    return C3, T, info


# ---------------------------------------------------------------- 扫描核心

def scan_task(task):
    """扫一个 [off, off+span) 区间。读取时多带 47 字节，避免 48 字节窗口跨块丢失。"""
    path, off, span, stride, c3_hex, T, prefilter = task
    C3 = bytes.fromhex(c3_hex)
    hits = []
    with open(path, "rb") as f:
        f.seek(off)
        buf = f.read(span + 47)
    n = len(buf)
    i = 0
    while i < span and i + 48 <= n:
        k = buf[i + 16:i + 48]
        if prefilter and (k.count(0) > 4 or len(k.translate(None, PRINTABLE)) < 6):
            i += stride
            continue
        p = Cipher(algorithms.AES(k), modes.ECB()).decryptor().update(C3)
        x = int.from_bytes(p, "little")
        if ((x >> 64) ^ (x & 0xFFFFFFFFFFFFFFFF)) == T:
            hits.append((path, off + i, k.hex()))
        i += stride
    return hits


def full_check(master, footer48):
    """用完整 CBC 解密复核并取出该文件的 file_key / nonce。"""
    d = Cipher(algorithms.AES(master[16:48]), modes.CBC(master[0:16])).decryptor()
    rec = d.update(footer48) + d.finalize()
    if rec[32:40] != rec[40:48]:
        return None
    return rec


# ---------------------------------------------------------------- 自检

def selftest(size=4 << 20, stride=1):
    print("== 自检 ==")
    master = os.urandom(48)
    file_key, nonce = os.urandom(32), os.urandom(8)
    rec = file_key + nonce + nonce
    e = Cipher(algorithms.AES(master[16:48]), modes.CBC(master[0:16])).encryptor()
    footer48 = e.update(rec) + e.finalize()
    C2, C3 = footer48[16:32], footer48[32:48]
    T = (int.from_bytes(C2[0:8], "little") ^ int.from_bytes(C2[8:16], "little"))

    tmpdir = tempfile.mkdtemp(prefix="c3selftest.")
    carrier = os.path.join(tmpdir, "carrier.bin")
    # 生成一片随机数据并在随机偏移埋入主密钥
    with open(carrier, "wb") as f:
        f.write(os.urandom(size))
    pos = random.randrange(4096, size - 4096)
    with open(carrier, "r+b") as f:
        f.seek(pos)
        f.write(master)

    print("数据 %.1f MiB，主密钥埋在偏移 0x%x，步长 %d" % (size / 1024 ** 2, pos, stride))
    t0 = time.time()
    hits = scan_task((carrier, 0, os.path.getsize(carrier), stride,
                      C3.hex(), T, False))
    dt = time.time() - t0
    print("扫描耗时 %.1f s（%.1f MB/s），命中 %d 处" % (dt, size / dt / 1e6, len(hits)))

    ok = True
    if len(hits) == 1 and hits[0][1] == pos and hits[0][2] == master[16:48].hex():
        print("PASS  命中唯一且偏移、密钥都对")
        got = full_check(master, footer48)
        if got and got[:32] == file_key and got[32:40] == nonce:
            print("PASS  完整 CBC 复核取出 file_key/nonce 一致")
        else:
            print("FAIL  完整复核不一致")
            ok = False
    else:
        print("FAIL  期望 1 处命中于 0x%x，实际 %d 处：%s" % (pos, len(hits), hits[:3]))
        ok = False

    # 空白对照：同一片随机数据，不埋密钥，必须 0 命中
    blank = os.path.join(tmpdir, "blank.bin")
    with open(blank, "wb") as f:
        f.write(os.urandom(4 << 20))
    neg = scan_task((blank, 0, os.path.getsize(blank), stride, C3.hex(), T, False))
    if neg:
        print("FAIL  空白对照出现误报（%d 处）" % len(neg))
        ok = False
    else:
        print("PASS  空白对照 0 命中")

    for p in (carrier, blank):
        try:
            os.remove(p)
        except OSError:
            pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass

    print("== 自检%s ==" % ("通过" if ok else "失败"))
    return 0 if ok else 1


# ---------------------------------------------------------------- 主流程

def build_tasks(sources, stride, C3, T, prefilter, chunk):
    tasks = []
    total = 0
    for p in sources:
        sz = os.path.getsize(p)
        total += sz
        off = 0
        while off < sz:
            span = min(chunk, sz - off)
            tasks.append((p, off, span, stride, C3.hex(), T, prefilter))
            off += span
    return tasks, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", help="任一 .L0CK3D 文件，用来取页脚做校验目标")
    ap.add_argument("--sources", nargs="*", default=[],
                    help="内存镜像 / 交换镜像，支持通配符")
    ap.add_argument("--stride", type=int, default=1, help="候选步长，1=全偏移（默认）")
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 2))
    ap.add_argument("--chunk", type=int, default=32 << 20)
    ap.add_argument("--no-prefilter", action="store_true", help="关闭前置过滤（慢约 10 倍）")
    ap.add_argument("--selftest", action="store_true", help="跑自检（合成密钥 → 精确命中）")
    ap.add_argument("--selftest-only", action="store_true", help="只跑自检")
    ap.add_argument("--selftest-size", type=int, default=4 << 20,
                    help="自检数据大小（字节），默认 4 MiB")
    a = ap.parse_args()

    if a.selftest or a.selftest_only:
        rc = selftest(size=a.selftest_size, stride=a.stride)
        if a.selftest_only or rc != 0:
            return rc
        print()

    if not a.sample or not a.sources:
        ap.print_help()
        return 1

    C3, T, info = load_sample(a.sample)
    print("校验目标  %s" % info["path"])
    print("会话标记  %s   模式 %s   pct=%d   原始大小 %d"
          % (info["marker"], info["mode"], info["pct"], info["osz"]))

    srcs = []
    for pat in a.sources:
        hits = glob.glob(pat)
        srcs.extend(hits if hits else [pat])
    srcs = [p for p in srcs if os.path.exists(p)]
    tasks, total = build_tasks(srcs, a.stride, C3, T, not a.no_prefilter, a.chunk)
    print("数据源    %d 个，%.2f GiB" % (len(srcs), total / 1024 ** 3))
    print("步长      %d（候选数约 %.2e）  worker %d" % (a.stride, total / a.stride, a.workers))
    print()

    from multiprocessing import Pool
    t0 = time.time()
    found = []
    done = 0
    with Pool(a.workers) as pool:
        for hits in pool.imap_unordered(scan_task, tasks, chunksize=1):
            done += 1
            for h in hits:
                print("HIT  %s @0x%x  key=%s" % h)
                found.append(h)
            if done % 20 == 0 or done == len(tasks):
                el = time.time() - t0
                print("  %d/%d  %.1f MB/s  %.0fs"
                      % (done, len(tasks), total / el / 1e6, el), flush=True)
    el = time.time() - t0
    print("\n完成 %.1fs（%.1f MB/s）" % (el, total / el / 1e6))

    if not found:
        print("NO_MATCH  没有候选通过 64 位校验")
        print("若已跑过 --selftest 且通过，则密钥确实不在这批镜像里；")
        print("最可能的原因是加密进程已退出并清零了密钥缓冲，见 docs/02-key-scan.md")
        return 2

    print("\n=== 完整复核 ===")
    with open(a.sample, "rb") as f:
        f.seek(-FOOT, os.SEEK_END)
        footer = f.read(FOOT)
    for path, off, khex in found:
        with open(path, "rb") as f:
            f.seek(off)
            master = f.read(48)
        got = full_check(master, footer[:48])
        if got:
            print("%s @0x%x" % (path, off))
            print("  master   = %s" % master.hex())
            print("  file_key = %s   nonce = %s" % (got[:32].hex(), got[32:40].hex()))
            print("  → 可用 c3dec.py 对整卷解密")
        else:
            print("%s @0x%x  完整复核未通过（可能是误报）" % (path, off))
    return 0


if __name__ == "__main__":
    sys.exit(main())
