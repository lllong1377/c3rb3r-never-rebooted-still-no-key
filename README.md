# 从未重启，仍然没有密钥：C3RB3R (.L0CK3D) 内存取证失败案例（13.5 GiB 全扫 0 命中）

**C3RB3R RAM key recovery, with the machine never rebooted — and it still failed.** The box ran continuously for 149 days with no reboot before or after the encryption. It failed anyway, because the encryptor process had already exited and zeroed its 48-byte key buffer.

2026 年 10 月这一波群晖 / 黑群晖 NAS 勒索事件里，公开的成功案例都建立在同一个前提上：**发现时加密进程还活着**。这个仓库记录的是另一种情况——机器从头到尾没有重启、没有关机，但加密进程早已退出，13.5 GiB 的物理内存与交换镜像全扫一遍，一个密钥都没有。

**一句话结论：未重启不等于有救。该看的是加密进程还在不在，不是机器有没有重启过。**

它不提供解密器，也不声称恢复了任何数据。它提供的是三样东西：一个可信的「没找到」结论、一套可复现的取数方法、以及一组让人少走弯路的实测数字。

## 三十秒版本

- 加密在 `2026-10-28 12:28` 结束，内存镜像采集于 `2026-10-29 18:53:14`，**相隔 30 小时 25 分**。机器 uptime 149 天，全程未重启。
- 采集 8.5 GB 物理内存（AVML，57 秒）+ 6 个 zram 交换镜像（各 831 MB），合计 13.5 GiB，**全偏移步长 1 字节**扫描，20 进程跑 1,591 秒。
- 结果 **NO_MATCH**。扫描前先跑自检：合成主密钥埋进随机数据，要求精确命中 1 处、空白对照 0 命中——通过。所以这个「没有」是可信的。
- 该看的不是「有没有重启」，而是「**加密进程还在不在**」。样本在退出路径会主动清零那 48 字节密钥缓冲，进程一走密钥就没了。

## 和已有四个仓库的不同

这一波已经有几个质量很高的公开项目，本仓库不重复它们的工作：

| 仓库 | 内容 | 与本案的关系 |
|---|---|---|
| [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue) | 首个成功案例（PVE 虚拟机）+ 格式分析与解密工具 | 解密请用它 |
| [Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue) | 第二个成功案例（物理机 / 黑群晖），冻结进程读 `/proc/PID/mem` | 本案是它的反面：没赶上窗口 |
| [Ericality/c3rb3r-dsm-case-20261028](https://github.com/Ericality/c3rb3r-dsm-case-20261028) | 案例记录，加密器因 OOM 自行退出 | 同属「进程没了」的结局 |
| [Creeper-OF/synology-c3rb3r-nas-case-study](https://github.com/Creeper-OF/synology-c3rb3r-nas-case-study) | 案例研究，`/proc/kcore` 采集、密钥未命中、残存数据恢复 | 结论方向一致；本仓库补采集中间环节 |
| **本仓库** | 整机不关机采集 + 证明「没找到」不是扫错 + 页脚清点工具 | — |

四个仓库都在讲「拿到了」或「没拿到」，本仓库补的是中间那一段：**当你决定「试试看能不能从内存里捞」时，具体怎么取、怎么扫、怎么证明结论不是扫错。**

## 本案事实

| 项目 | 值 |
|---|---|
| 机型 | 黑群晖（自组装，i5-8500T / 6 核 / 8 GB）；引导器伪装 DS918+，`uname` 报 `synology_apollolake_918+`，DMI `product_name=Synoden` |
| 系统 | DSM 7.2.0-64570 Update 3，内核 4.4.302+，btrfs |
| 采集时 uptime | 149 天 7 小时 46 分（感染期间未重启） |
| 加密规模 | 892,384 个 `.L0CK3D`；密文覆盖约 470 GiB（12.9%），其余 87.1% 为明文残留 |
| 唯一在意的资产 | 一个 16.9 MB 的 SQLite 主库 + 9 份日备，**全部 `0x24` 整文件加密，零明文** |
| 密钥 | **未取得**。页脚会话标记 `038c0ac9` |
| 处置 | 清除 `/etc/cron.d/synot*` 持久化、封 C2、隔离留证；未付赎金 |

时间线：`10/28 10:46` 首批勒索信 → `12:28` 主体批次落盘、进程退出 → `10/29 18:53` 发现并采集内存。**全程没有关机、没有重启。**

## 工具

四个脚本，只用 Python 标准库 + `cryptography`（唯一依赖），不依赖样本、不依赖网络。

| 脚本 | 作用 |
|---|---|
| `tools/capture-live.sh` | 现场采集：空间检查 → 可疑进程快照 → AVML 取内存 → 校验 → zram/分区交换采集 |
| `tools/lime_parse.py` | 解析 LiME 段结构：段数、捕获量、物理范围、空洞、字节核对（判断镜像是否被截断） |
| `tools/scan_master.py` | 全偏移扫描会话主密钥；`--selftest` 用合成密钥验证扫描器本身 |
| `tools/footer.py` | 页脚解析与全卷清点：模式分布、密文覆盖、残存明文比例 |

```sh
# 1. 先证明扫描器能工作（约 25 秒）
python3 tools/scan_master.py --selftest

# 2. 检查镜像完整性
python3 tools/lime_parse.py memdump.lime --json segs.json

# 3. 全偏移扫描（13.5 GiB / 20 核约半小时；拉回电脑跑，别在 NAS 上跑）
python3 tools/scan_master.py --sample /path/any.L0CK3D \
    --sources memdump.lime 'swap-zram*.img' --stride 1 --workers 20

# 4. 不解密，先算清楚还有多少东西可用
python3 tools/footer.py --dir /volume1/share --csv triage.csv
```

扫描命中会直接打印 `master` 与 `file_key/nonce`，接下来用上游的 `c3dec.py` 解密即可。**本仓库不含解密器**——本案没拿到密钥，写一个没在本案验证过的解密器没有意义。

## 文档

- [01 · 不关机采集](docs/01-live-acquisition.md)：AVML 在满卷 DSM 上的可行性、LiME 段结构、zram 才是交换真正存数据的地方、传输权限的几个坑
- [02 · 密钥扫描](docs/02-key-scan.md)：64 位校验原理、**「没找到」必须先通过自检**、NO_MATCH 的四种解释
- [03 · 页脚清点](docs/03-volume-triage.md)：不解密算出密文覆盖、为什么 87% 明文不等于 87% 可恢复
- [04 · IOC 与处置](docs/04-iocs.md)：投放链、会自我重建的 cron 持久化、彻底清除的先后顺序

## 如果刚中招：按这个顺序判断

1. **先看进程在不在**：`ls -l /proc/*/exe 2>/dev/null | grep deleted`
   - 有输出 → 别重启、别 `kill -9`，先 `kill -STOP <PID>`，然后按 [Benjamin-zlt 的流程](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue) 取进程内存。**这是唯一有机会全解的路。**
   - 没输出 → 继续第 2 步。
2. **确认加密结束多久了**。以小时计，整机取内存的意义已经很小（本文档 02 篇）；以分钟计，值得一试。
3. **先做页脚清点**，搞清楚核心资产落在哪个模式。如果核心资产全是 `0x24`，那就别再指望残存数据重建，把精力转到「找站外副本」和「重建」上。
4. **保全**：`.L0CK3D` 原样留着、未加密部分尽快拷出来、把勒索信和日志留档。
5. **根除**：清持久化 + 封 C2 + 打补丁 + 改凭据，四件一起做。

## 这份记录不能声称什么

- 不能声称恢复成功。本案核心数据（10 个 SQLite 数据库）在密码学上不可恢复，除非有站外副本或出现针对该会话的工具。
- 不能声称「整机取内存是通用解法」。它只是在进程已退出时唯一还能做的那件事，且本案证明它常常给出零结果。
- 不能声称「87% 明文等于 87% 可恢复」。见 [03](docs/03-volume-triage.md)：头尾被切之后，很多文件类型根本无法重建。
- 不包含受害者标识、门户链接、内网地址、账号、业务数据或可执行攻击载荷。所有 IOC 均为攻击方基础设施。

## 许可

代码 MIT；文档 CC BY 4.0。引用或改写请保留出处。

## 致谢

方法与格式认知来自 [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue) 与 [Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue) 的公开工作，页脚字段与分段规则以他们的 `c3dec.py` 为准，本案独立复核一致。本条目不构成对任何第三方服务的推荐。
