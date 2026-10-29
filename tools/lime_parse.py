#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LiME 内存镜像段结构解析 / LiME segment parser.

AVML 的 `--format lime` 输出不是裸内存，而是「段头 + 段数据」重复拼接：
    32 字节头：magic(u32 LE, 0x4C694D45) | version(u32) | s(u64) | e(u64) | reserved(8)
    段长 = e - s + 1
注意落盘后的 magic 字节序是 45 4d 69 4c，按 u32 LE 读出才是 0x4C694D45。
段长是 e-s+1 而不是 e-s，差一个字节；按 e-s 算会从第二段开始全错。

用法：
    python3 lime_parse.py memdump.lime
    python3 lime_parse.py memdump.lime --json segments.json
    python3 lime_parse.py memdump.lime --list 20
"""
import argparse
import json
import os
import struct
import sys

HEADER_LEN = 32
MAGIC = 0x4C694D45


def parse(path):
    size = os.path.getsize(path)
    segs = []
    problems = []
    off = 0
    with open(path, "rb") as f:
        while off < size:
            if size - off < HEADER_LEN:
                problems.append("尾部残余 %d 字节，不足一个段头（可能被截断）" % (size - off))
                break
            f.seek(off)
            h = f.read(HEADER_LEN)
            magic, version = struct.unpack("<II", h[0:8])
            if magic != MAGIC:
                problems.append("偏移 0x%x 处 magic=0x%08x 不是 LiME 段头" % (off, magic))
                break
            s, e = struct.unpack("<QQ", h[8:24])
            if e < s:
                problems.append("偏移 0x%x 处 s=0x%x > e=0x%x，段头损坏" % (off, s, e))
                break
            ln = e - s + 1
            data_off = off + HEADER_LEN
            if data_off + ln > size:
                problems.append(
                    "偏移 0x%x 处声明段长 0x%x（%d 字节），但文件只剩 %d 字节 → 镜像被截断"
                    % (off, ln, ln, size - data_off))
                break
            segs.append({"s": s, "e": e, "len": ln, "header_off": off,
                         "data_off": data_off, "version": version,
                         "reserved": h[24:32].hex()})
            off = data_off + ln
    return segs, problems, size


def summarize(segs, size):
    st = {}
    st["segments"] = len(segs)
    st["file_size"] = size
    st["captured"] = sum(x["len"] for x in segs)
    st["overhead"] = len(segs) * HEADER_LEN
    if segs:
        st["phys_min"] = min(x["s"] for x in segs)
        st["phys_max"] = max(x["e"] for x in segs)
        ordered = sorted(segs, key=lambda x: x["s"])
        gaps, overlaps = [], []
        for a, b in zip(ordered, ordered[1:]):
            if b["s"] > a["e"] + 1:
                gaps.append((a["e"] + 1, b["s"] - 1))
            elif b["s"] <= a["e"]:
                overlaps.append((b["s"], min(a["e"], b["e"])))
        st["gaps"] = gaps
        st["overlaps"] = overlaps
        st["gap_bytes"] = sum(e - s + 1 for s, e in gaps)
        st["coverage"] = st["captured"] + st["gap_bytes"]
        st["versions"] = sorted({x["version"] for x in segs})
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--json", metavar="OUT", help="把段表与统计写成 JSON")
    ap.add_argument("--list", type=int, default=0, metavar="N", help="列出前 N 段")
    a = ap.parse_args()

    segs, problems, size = parse(a.image)
    st = summarize(segs, size)

    print("镜像文件  %s  %d 字节 (%.2f GiB)" % (a.image, size, size / 1024 ** 3))
    print("段数      %d    头部开销 %d 字节" % (st["segments"], st["overhead"]))
    print("捕获内存  %.3f GiB (%d 字节)" % (st["captured"] / 1024 ** 3, st["captured"]))
    if segs:
        print("物理范围  0x%x .. 0x%x" % (st["phys_min"], st["phys_max"]))
        print("段头版本  %s" % st["versions"])
        print("段间空洞  %d 处，合计 %.3f GiB（PCI/保留区，正常）"
              % (len(st["gaps"]), st["gap_bytes"] / 1024 ** 3))
        if st["overlaps"]:
            print("段间重叠  %d 处 ← 异常" % len(st["overlaps"]))
        if st["captured"] + st["overhead"] == size:
            print("字节核对  捕获 + 头部 = 文件长度，无残余")
        else:
            print("字节核对  捕获 + 头部 = %d，与文件长度 %d 不符 ← 需检查"
                  % (st["captured"] + st["overhead"], size))
        for s, e in st["gaps"][:6]:
            print("            空洞 0x%x..0x%x (%.1f MiB)" % (s, e, (e - s + 1) / 1024 ** 2))
        if len(st["gaps"]) > 6:
            print("            …其余 %d 处" % (len(st["gaps"]) - 6))

    if a.list:
        print("\n前 %d 段：" % min(a.list, len(segs)))
        print("  #   header_off   data_off     phys_s       phys_e       len")
        for i, x in enumerate(segs[:a.list]):
            print("  %-3d 0x%08x   0x%08x   0x%09x  0x%09x  0x%x"
                  % (i, x["header_off"], x["data_off"], x["s"], x["e"], x["len"]))

    for p in problems:
        print("问题：%s" % p)

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"image": os.path.abspath(a.image), "summary": st,
                       "problems": problems, "segments": segs}, f, indent=1)
        print("\n已写出 %s" % a.json)

    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
