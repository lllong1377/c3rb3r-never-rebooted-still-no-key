#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C3RB3R 加密文件页脚解析与全卷清点 / .L0CK3D footer parser and volume triage.

页脚固定 588 字节，格式（偏移均相对页脚起点；来源：soimy/c3rb3r-rescue、
Benjamin-zlt/c3rb3r-baremetal-rescue 的 c3dec.py，本案独立核对一致）：

    0..48    AES-256-CBC 包裹的「file_key(32) + nonce(8) + nonce(8)」
    568..572 会话标记（4 字节，每次运行不同，同一会话内一致）
    572      文件模式：0x24 整文件 / 0x25 分段 / 0x26 仅前 1 MiB
    573      分段参数 pct（仅 0x25 有意义）
    574      加密模式：0x20 真加密 / 0x21 诱饵
    580..588 原始大小（u64 LE，不含页脚）

用途：不解密也能判断「这份数据到底还有多少明文可用」。
模式决定密文覆盖范围，覆盖范围决定残存数据的天花板。

用法：
    python3 footer.py /path/to/file.db.L0CK3D
    python3 footer.py --dir /volume1/share --csv triage.csv
    python3 footer.py --dir /volume1/share --summary-only
"""
import argparse
import csv
import os
import struct
import sys

FOOT = 588
FIRST = 1024 * 1024

# 分段模式下 pct → 每段占原文件的百分比。取值来自 c3dec.py（PF 表），
# 未列出的 pct 视为未知，不参与密文量估算。
PF = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12, 40: 14, 50: 10, 60: 20, 70: 23, 80: 27}

MODE_NAME = {0x24: "full", 0x25: "segmented", 0x26: "first-1MiB"}


def read_footer(path):
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size < FOOT:
            return None, size
        f.seek(-FOOT, os.SEEK_END)
        return f.read(FOOT), size


def parse(footer, filesize):
    marker = footer[568:572]
    mode, pct, cm, _ = footer[572:576]
    osz = struct.unpack_from("<Q", footer, 580)[0]
    d = {
        "marker": marker.hex(),
        "mode": "0x%02x" % mode,
        "mode_name": MODE_NAME.get(mode, "unknown"),
        "pct": pct,
        "crypto": "0x%02x" % cm,
        "osz": osz,
        "filesize": filesize,
        "size_ok": (osz + FOOT == filesize),
    }
    d["enc_bytes"], d["enc_note"] = encrypted_bytes(osz, mode, pct)
    return d


def encrypted_bytes(osz, mode, pct):
    """密文覆盖字节数；无法判定时返回 (None, 原因)。"""
    if mode == 0x24:
        return osz, "整文件"
    if mode == 0x26:
        return min(osz, FIRST), "前 1 MiB"
    if mode == 0x25:
        if pct not in PF:
            return None, "pct=%d 不在已知表内，无法估算" % pct
        ln = (osz // 100) * PF[pct]
        cnt = 5 if pct == 50 else 3
        return ln * cnt, "%d 段 × %d%%" % (cnt, PF[pct])
    return None, "未知模式 0x%02x" % mode


def crash_free_ratio(osz, enc):
    """残存明文占比。注意：分段模式下头尾被切，明文段虽在但文件结构可能不完整。"""
    if not osz or enc is None:
        return None
    return max(0.0, 1.0 - enc / float(osz))


def show(path):
    footer, size = read_footer(path)
    if footer is None:
        print("文件小于 %d 字节，不是 C3RB3R 加密文件：%s" % (FOOT, path))
        return 1
    d = parse(footer, size)
    print("文件      %s" % path)
    print("大小      %d 字节（页脚 588）→ 原始大小 %d" % (size, d["osz"]))
    print("会话标记  %s" % d["marker"])
    print("模式      %s (%s)   pct=%d   加密模式 %s"
          % (d["mode"], d["mode_name"], d["pct"], d["crypto"]))
    print("大小核对  %s" % ("一致" if d["size_ok"] else "不一致 ← 可能有追加数据或截断"))
    if d["enc_bytes"] is None:
        print("密文范围  未知（%s）" % d["enc_note"])
    else:
        print("密文范围  %d 字节（%s）  残存明文约 %.1f%%"
              % (d["enc_bytes"], d["enc_note"], 100 * crash_free_ratio(d["osz"], d["enc_bytes"])))
    if d["crypto"] == "0x21":
        print("注意      0x21 是诱饵材料，即使拿到会话密钥也解不开")
    return 0


def walk(root, csv_path, summary_only):
    rows = []
    bad = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [x for x in dirnames if x not in ("#recycle", "@eaDir")]
        for name in filenames:
            if not name.endswith(".L0CK3D"):
                continue
            p = os.path.join(dirpath, name)
            try:
                footer, size = read_footer(p)
            except OSError:
                bad += 1
                continue
            if footer is None:
                bad += 1
                continue
            d = parse(footer, size)
            d["path"] = p
            rows.append(d)

    by_mode = {}
    for d in rows:
        k = d["mode_name"] if d["enc_bytes"] is not None else "unknown"
        s = by_mode.setdefault(k, {"files": 0, "osz": 0, "enc": 0})
        s["files"] += 1
        s["osz"] += d["osz"]
        s["enc"] += d["enc_bytes"] or 0

    print("扫描根目录  %s" % root)
    print("加密文件    %d 个（读取失败 %d）" % (len(rows), bad))
    tot_osz = sum(d["osz"] for d in rows)
    tot_enc = sum(d["enc_bytes"] or 0 for d in rows)
    print("原始总量    %.2f GiB" % (tot_osz / 1024 ** 3))
    print("密文覆盖    %.2f GiB（%.1f%%）" % (tot_enc / 1024 ** 3,
                                            100.0 * tot_enc / tot_osz if tot_osz else 0))
    print()
    print("  %-12s %10s %12s %12s %8s" % ("模式", "文件数", "原始 GiB", "密文 GiB", "密文占比"))
    for k in sorted(by_mode, key=lambda x: -by_mode[x]["files"]):
        s = by_mode[k]
        pct = 100.0 * s["enc"] / s["osz"] if s["osz"] else 0
        print("  %-12s %10d %12.2f %12.2f %7.1f%%"
              % (k, s["files"], s["osz"] / 1024 ** 3, s["enc"] / 1024 ** 3, pct))

    markers = {}
    for d in rows:
        markers[d["marker"]] = markers.get(d["marker"], 0) + 1
    print("\n会话标记：%s" % ", ".join("%s×%d" % (k, v)
                                     for k, v in sorted(markers.items(), key=lambda x: -x[1])[:6]))
    if len(markers) > 1:
        print("注意：出现多个标记 → 可能经历多次加密，或混入了其他机器的数据")

    if csv_path and not summary_only:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["path", "filesize", "osz", "marker", "mode", "mode_name",
                        "pct", "crypto", "size_ok", "enc_bytes", "enc_note"])
            for d in rows:
                w.writerow([d["path"], d["filesize"], d["osz"], d["marker"], d["mode"],
                            d["mode_name"], d["pct"], d["crypto"], d["size_ok"],
                            d["enc_bytes"], d["enc_note"]])
        print("\n明细已写出 %s（%d 行）" % (csv_path, len(rows)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="单个 .L0CK3D 文件")
    ap.add_argument("--dir", help="递归解析一个目录")
    ap.add_argument("--csv", help="明细 CSV 输出路径")
    ap.add_argument("--summary-only", action="store_true", help="只打汇总，不写 CSV")
    a = ap.parse_args()
    if a.dir:
        return walk(a.dir, a.csv, a.summary_only)
    if a.file:
        return show(a.file)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
