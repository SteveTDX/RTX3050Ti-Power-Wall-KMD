# RTX 3050 Ti Laptop 8GB 功耗墙突破（KMD 驱动级）

> 在 **RTX 3050 Ti Laptop GPU（GA107, 8 GB 魔改，原厂 60 W）** 上，通过**重编译 NVIDIA 内核显示驱动（nvlddmkm）的电源策略模块**并测试签名加载，将功耗上限提升至 85 / 90 W。
> 状态：**已验证通过**（90 W 写入成功，420 秒满载稳定）。推荐档位 **85 W**。

本仓库是完整的技术复现包：原理文档 + 反汇编适配脚本 + 驱动源码 + 部署脚本 + 实测数据。

---

## 1. 实测结果

RTX 3050 Ti Laptop 8 GB / 驱动 617.42 / CUDA 12.4 / PyTorch FP16 GEMM（8192³）满载 420 s：

| 功耗上限 | 实测整卡功耗 | 平均核心频率 | 算力 (FP16) | 终温 | 相对 60 W |
|---|---:|---:|---:|---:|---:|
| 60 W（原厂） | 59.70 W | ~1700 MHz | 16.86 TFLOPS | 49 °C | 基线 |
| 70 W | 69.57 W | 1740 MHz | 17.56 TFLOPS | 66 °C | **+4.2 %** |
| **85 W（推荐）** | 76.43 W | 1860 MHz | 18.00 TFLOPS | 70 °C | **+6.8 %** |
| 90 W | 77.82 W | 1887 MHz | 18.03 TFLOPS | 71 °C | +6.9 % |

**结论**：本机硬件实际天花板约 **78 W**——90 W 仅比 85 W 多 0.2 % 算力却多 1 °C，故 85 W 为性能/温度最优点。功耗上限继续抬高不会带来收益，瓶颈已从"策略墙"转移到"硅片/散热/适配器"。

---

## 2. 技术路线：为什么必须重编驱动

三类常规手段在本机全部失效，这是本项目的起点：

| 手段 | 失效原因 |
|---|---|
| `nvidia-smi -pl` | 移动版 SKU 的 `power.limit` 报 `N/A`，VBIOS 无对应接口 |
| MSI Afterburner / INNO3D TuneIT | 只能调 Core/Memory Offset 与电压曲线，无法改写 TGP 策略对象 |
| 直接刷 VBIOS | Ampere 起 VBIOS 采用 **BCRT 2.0 + HMAC 验签**，改过的镜像拒绝加载；且失败即变砖 |

可行路径只有一条：**在运行时直接改写驱动内的电源策略对象**。而原厂 `Nvpwr.sys` 会对 `nvlddmkm.sys` 的 PE 身份做硬校验（`TimeDateStamp` + `SizeOfImage`），并以只读方式校验策略对象不变式，因此必须**按本机驱动重新适配并重编译**。

核心概念（详见技术文档第 4 章）：

- `UPPER` / `LowerBoundary`：策略对象的功耗上下界，原厂 `UPPER = 60000`（mW）
- `CTGP` / `F7`：当前生效 TGP 值
- `PPAB amount`：动态预算增量，受 **`Amount ≤ Upper − Lower`** 约束
- IOCTL 状态机：`CONTEXT_INVALID → MIXED → STOCK_BASELINE → APPLIED`

三处关键源码改动（`src/src/driver/driver.c`）：

1. 容忍 stock 态下惰性未激活的 `F7`（`CurrentF7Value == INVALID_POWER`）
2. StockBaseline 校验移除硬编码 `UpperBoundary >= 100000`，接受 GA107 的固定下限
3. `ResolvePpabAmount()` 按实际余量 `headroom = *upper − *lower` 动态计算，而非固定常量

---

## 3. 仓库结构

```
.
├─ RTX3050Ti功耗墙突破技术文档.md   ★ 主文档：11 章完整技术路径（原理/工具链/改动/签名/实测/踩坑）
├─ 3050Ti功耗解锁研究报告.md        前置调研：四条路线可行性对比与本机基线实测
├─ docs/                           工具用户手册（中/英 PDF）
├─ src/                            驱动与 CLI 源码
│  ├─ src/driver/driver.c          ★ 核心：电源策略改写 IOCTL 实现
│  ├─ src/driver/nvpwr_target.h
│  ├─ src/cli/nvpwrctl.cpp         命令行控制端
│  ├─ src/shared/nvpwr_ioctl.h     两端共享 IOCTL 契约
│  ├─ tools/adapt.py               ★ 自动发现本机驱动的 PE 时间戳/SizeOfImage/RVA 锚点
│  ├─ tools/{anchors,signatures,discover}.py   反汇编锚点定位
│  ├─ tools/ensure-dependencies.ps1            capstone/WDK/NuGet 依赖拉取
│  └─ build.ps1 / build.cmd
└─ scripts/
   ├─ deploy/                      生产环境部署脚本（85 W 开机自启）
   │  ├─ apply_power.ps1           写入指定功耗上限
   │  ├─ restore_power.ps1         回退原厂 60 W
   │  ├─ install_boottask.ps1      注册开机自启计划任务
   │  ├─ set-70w.cmd / set-85w.cmd / set-90w.cmd / restore-60w.cmd
   │  └─ install-boot-85w.cmd      一键安装 85 W 开机任务
   └─ script_for_RTX3050Ti_Mobile_8Gb/   验证阶段的原始 .cmd 脚本（保留全过程痕迹）
```

---

## 4. 前置条件（缺一不可）

| 条件 | 要求 | 检查方式 |
|---|---|---|
| Secure Boot | **必须关闭** | `Confirm-SecureBootUEFI` |
| HVCI / 内存完整性 | 必须未启用 | `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` |
| 测试签名模式 | **需开启**（加载自签驱动） | `bcdedit /enum {current}` 中 `testsigning Yes` |
| 驱动版本 | 需与本机 `nvlddmkm.sys` 完全匹配后重新适配 | 见 `src/tools/adapt.py` |
| 管理员权限 | 部署与 IOCTL 均需提权 | — |

⚠️ 驱动版本不同（PE 时间戳 / SizeOfImage 变化）时，**必须重跑 `adapt.py` 重新生成锚点**，直接套用他人产物会返回 `Win32=31` 或直接蓝屏。

---

## 5. 快速使用

```powershell
# 1) 构建（自动拉取 capstone / WDK / Windows SDK）
cd src
.\build.ps1            # 产物: out\output\dist\Nvpwr.sys + NvpwrCtl.exe

# 2) 切换档位（管理员）
cd ..\scripts\deploy
.\set-85w.cmd          # 或 set-90w / set-70w

# 3) 回退原厂
.\restore-60w.cmd

# 4) 注册开机自启（85 W）
.\install-boot-85w.cmd
```

**重要操作约束**：工具仅支持"从原厂态一次性设定"目标值。若要改档，必须 `restore → set` 两段式，直接在已应用态上再次 set 会失败。

---

## 6. 风险提示

- 本质是**未签名内核驱动的运行时改写**，蓝屏（BSOD）是本项目的常态风险。开发期已记录多份 `*.dmp`，建议在无重要任务时操作并准备安全模式回退。
- 提升 TGP 会同步抬高 VRM 与散热模组负载。**本机 85 W 稳态核心 70 °C**，属可接受区间；若环境温度更高或散热积灰，请下调至 70 W。
- 笔记本电源适配器总功率需留余量（本机 700 W，无瓶颈）。
- 请自行确认当地法律与保修条款；本项目仅供个人研究与学习，**不对任何硬件损坏或数据丢失承担责任**。
- 严禁对非自有设备、租赁设备或商用设备执行本流程。

---

## 7. 文档

| 文档 | 内容 |
|---|---|
| [RTX3050Ti功耗墙突破技术文档.md](RTX3050Ti功耗墙突破技术文档.md) | 11 章 + 2 附录：原理、工具链、三处源码改动、签名流程、实测、完整操作手册、踩坑记录、给后续 Agent 的建议 |
| [3050Ti功耗解锁研究报告.md](3050Ti功耗解锁研究报告.md) | 四条路线（驱动改写 / 注册表影子 / VBIOS / 工具软件）可行性对比与风险清单 |
| `docs/*.pdf` | NvpwrControl Stage11 用户手册（中 / 英） |

---

## 8. 相关仓库

- [RTX3050Ti-8G-Toolkit](https://github.com/SteveTDX/RTX3050Ti-8G-Toolkit) —— vBIOS 备份/刷写与跨 Win10/11 自适应预检工具箱，属另一条技术路线，可与本项目互补。

## 免责声明

本项目涉及 NVIDIA 内核驱动的反向工程与修改，与 NVIDIA Corporation 无任何关联。所有商标归其各自所有者。代码与文档按"现状"提供，不附带任何明示或暗示担保。
