#!/bin/sh
# C3RB3R 现场内存与交换采集（DSM 实机、不重启）/ live RAM + swap acquisition
#
# 用法（root）：
#   sh capture-live.sh /volume2/ir /path/to/avml
#
# 三条硬规则：
#   1. 不要重启。重启等于把内存里可能还活着的会话密钥彻底扔掉。
#   2. 不要 kill 加密进程。要冻住就 kill -STOP <PID>，见 docs/01-live-acquisition.md。
#   3. 输出卷必须有空间。DSM 上 /volume1 常常正是被写满的那个，别往那儿写。
#
# 本脚本只做采集与校验，不改动任何原有文件。

set -u

OUT="${1:-}"
AVML="${2:-}"
TS=$(date +%Y%m%d_%H%M%S)

die() { echo "错误：$*" >&2; exit 1; }

[ -n "$OUT" ] || die "用法：sh capture-live.sh <输出目录> <avml 二进制路径>"
[ -n "$AVML" ] || die "未指定 avml 二进制路径"
[ -f "$AVML" ] || die "找不到 $AVML"
[ "$(id -u)" = "0" ] || die "需要 root"

command -v sha256sum >/dev/null 2>&1 || die "缺少 sha256sum"

mkdir -p "$OUT" || die "无法创建 $OUT"

# 输出卷空间：内存镜像约等于 MemTotal，再留 10%
MEM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
NEED_KB=$(( MEM_KB + MEM_KB / 10 ))
FREE_KB=$(df -Pk "$OUT" | awk 'NR==2{print $4}')
echo "输出目录   $OUT"
echo "MemTotal   $(( MEM_KB / 1024 )) MiB   需要约 $(( NEED_KB / 1024 )) MiB   可用 $(( FREE_KB / 1024 )) MiB"
[ "$FREE_KB" -ge "$NEED_KB" ] || die "输出卷空间不足，换一个有空间的卷（/volume2、/volume3、外接盘）"

echo
echo "== 1. 现场状态（先留证据，再采集）=="
date
uptime
echo "--- 可疑进程（加密器常见形态：exe 指向 deleted 文件）"
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in
        *"(deleted)"*) echo "  PID ${p#/proc/}  exe=$exe";;
    esac
done
echo "--- 若上面出现加密器，先 kill -STOP <PID> 再继续，不要 kill -9"
echo

echo "== 2. 采集物理内存 =="
IMG="$OUT/memdump_$TS.lime"
echo "avml sha256: $(sha256sum "$AVML" | cut -d' ' -f1)"
start=$(date +%s)
"$AVML" --format lime --output "$IMG" || die "avml 采集失败"
end=$(date +%s)
chmod 444 "$IMG"
ls -l "$IMG"
echo "耗时 $(( end - start )) s"
sha256sum "$IMG" | tee "$IMG.sha256"
echo

echo "== 3. 交换设备 =="
cat /proc/swaps
echo
for dev in $(awk 'NR>1{print $1}' /proc/swaps); do
    case "$dev" in
        /dev/zram*)
            name=$(basename "$dev")
            echo "-- $dev 是 zram（压缩内存盘），dd 出来的是解压后的页"
            out="$OUT/swap-$name-$TS.img"
            dd if="$dev" of="$out" bs=1M 2>/dev/null
            chmod 444 "$out"
            ls -l "$out"
            sha256sum "$out" | tee "$out.sha256"
            ;;
        /dev/*)
            used=$(awk -v d="$dev" '$1==d{print $4}' /proc/swaps)
            if [ "${used:-0}" = "0" ]; then
                echo "-- $dev 使用量为 0，跳过（空交换区里没有东西）"
            else
                name=$(basename "$dev")
                out="$OUT/swap-$name-$TS.img"
                echo "-- $dev 已用 ${used} KB，按设备大小采集"
                dd if="$dev" of="$out" bs=1M 2>/dev/null
                chmod 444 "$out"
                ls -l "$out"
                sha256sum "$out" | tee "$out.sha256"
            fi
            ;;
    esac
done
echo

echo "== 4. 收尾 =="
echo "采集完成。下一步不要重启，也不要对原卷做任何写操作。"
echo "把 $OUT 整个目录下载到另一台机器做离线分析："
echo "  python3 tools/lime_parse.py memdump_$TS.lime --json segs.json"
echo "  python3 tools/scan_master.py --sample <任一 .L0CK3D> --sources '$OUT/*.lime' '$OUT'/swap-*.img --stride 1"
echo "扫描前务必先跑：python3 tools/scan_master.py --selftest"
