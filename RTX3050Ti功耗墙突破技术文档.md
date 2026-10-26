# RTX 3050 Ti Laptop (GA107) 功耗墙突破 —— 完整技术文档

> 目标：把本机 RTX 3050 Ti Laptop GPU 的 60W 功耗墙提升到 85–90W。
> 结果：**已达成**。90W 写入成功并通过 420 秒满载验证。
> 日期：2026-10-16
> 适用硬件：NVIDIA GeForce RTX 3050 Ti Laptop GPU (GA107, 8GB 魔改) + i7-11850H + HM570 准系统，驱动 617.32.0.1742

---

## 目录

1. [结论速览](#1-结论速览)
2. [硬件与系统基线](#2-硬件与系统基线)
3. [为什么必须重编驱动](#3-为什么必须重编驱动)
4. [技术原理：功耗策略对象](#4-技术原理功耗策略对象)
5. [工具链搭建](#5-工具链搭建)
6. [源码适配：三处关键改动](#6-源码适配三处关键改动)
7. [驱动签名与加载](#7-驱动签名与加载)
8. [实测性能数据](#8-实测性能数据)
9. [完整操作手册](#9-完整操作手册)
10. [已知限制与踩坑记录](#10-已知限制与踩坑记录)
11. [文件清单](#11-文件清单)

---

## 1. 结论速览

| 项目 | 结果 |
|---|---|
| 原厂功耗墙 | 60 W |
| 已验证可用档位 | 70 W / 85 W / 90 W |
| **推荐档位** | **85 W**（性能/温度性价比最优） |
| 85W 实测增益 | 算力 **+6.8%**，核心频率 +9.4%，温度 +21°C |
| 硬件实际天花板 | 约 78 W（GPU 自身吃不下更多） |
| 达成方式 | 源码重编 Nvpwr 驱动 + 测试签名加载 |
| 是否可回退 | 是，`restore` 命令随时恢复原厂 60W |

---

## 2. 硬件与系统基线

```
GPU          : NVIDIA GeForce RTX 3050 Ti Laptop GPU
架构         : GA107 (Ampere, AD107 衍生物)
PCI ID       : VEN_10DE / DEV_25A0 / SUBSYS_000010DE / REV_A1
显存         : 8192 MiB（4GB→8GB 魔改，依赖颗粒 JEDEC 密度自动识别）
VBIOS        : 94.07.3a.00.0e
驱动         : 617.42 (FileVersion 32.0.16.1742)
驱动 PE 身份 : TimeDateStamp=0x6ABD8060, SizeOfImage=0x06D45000
平台         : i7-11850H (Tiger Lake) + HM570 准系统
内存         : DDR4-3200
适配器       : 700 W（供电无瓶颈）
```

**关键前置条件检查**：

```
Secure Boot      : 已关闭（必须）
HVCI/内存完整性   : 未启用
testsigning      : 需开启（用于加载自签驱动）
Hyper-V/VBS      : 运行中（WSL2），不影响本方案
Defender         : 开启（需添加排除项）
```

---

## 3. 为什么必须重编驱动

### 3.1 上游工具的设计假设

Nvpwr 项目的目标是给 **RTX 40/50 系笔记本**突破功耗墙（那些机器 OEM TGP 通常 100–200W）。其状态机 `FillStatusFromContext` 中的 StockBaseline 判定硬编码：

```c
/* 原始代码 */
if (Out->UpperBoundary >= 100000u && Out->UpperBoundary <= 200000u &&   // 100W–200W
    Out->MaxEffective == Out->UpperBoundary &&
    ...
```

本机 `UpperBoundary = 60000`（60W），**永远无法满足** → 状态机判定为 `CONTEXT_INVALID` → `SetPowerTarget` 直接返回 `STATUS_INVALID_DEVICE_STATE`，不写任何内存。

### 3.2 预编译驱动的第二个死结

即使绕过状态判定，`SetPowerTarget` 还有第二道门：

```c
if (!g_BoardSetConfirmed) {
    // "Board type-0 setter RVA for target image is not confirmed"
    return STATUS_DEVICE_NOT_READY;
}
```

`g_BoardSetConfirmed` 是**编译期常量** `(RVA_BOARD_TYPE0_SET != 0)`。社区预编译的 `Nvpwr.sys` 该值为 0，意味着它会调用一个**未经签名验证的函数指针** —— 在内核态执行未确认地址 = 极高风险。

**二进制补丁无法解决第二点**（它是编译期常量），**只有源码重编才能内嵌正确的 RVA**。

### 3.3 VBIOS 路线为何不可行

本项目早期会话已完整验证（见 `D:/tmp/workbuddy_space/2026-10-14-21-01-54/`）：

| 尝试 | 结果 |
|---|---|
| nvflash 刷自改 ROM | `CERT20_VDPA_SIG_INVALID` |
| nvflashk 刷自改 ROM | 同上 |
| v1 补丁（跳主机侧验签）+ 自改 | GPU 侧 Falcon HALT |
| v2 补丁（NOP 验签调用）+ 原厂签名 ROM | `EWR_OK_TO_FLASH_CHECK_FAILED` |
| v1 + **原厂签名** ROM | ✅ 成功（证明通路本身可用） |
| 交叉刷 HP 官方签名 ROM（80W/95W） | 刷写成功，但**冷启动显存训练失败**，独显无法加载 |

**结论**：Ampere 的 BCRT 2.0 + HMAC 证书校验在显卡固件内完成，主机侧无法伪造。5 组实验闭环证明：GPU 只允许通过验签的镜像进入 EWR 流程。

---

## 4. 技术原理：功耗策略对象

### 4.1 nvlddmkm 内部的功耗策略层级

驱动在 `nvlddmkm.sys` 内存中维护一棵策略对象树：

```
DriverGlobal (RVA_GPU_GLOBAL)
  └─ GpuTable (OFF_GLOBAL_GPU_TABLE = 0x208)
       └─ Major Object (per-GPU)
            └─ PowerRoot (OFF_MAJOR_POWER_ROOT = 0x25B0)
                 ├─ +0x3D10  RootInitialized (UCHAR)
                 ├─ +0x3D11  Eligibility      (UCHAR)
                 ├─ +0x3D12  AmountActive     (UCHAR)
                 ├─ +0x3D14  CtgpTarget       (ULONG, mW)  ← 核心目标功耗
                 ├─ +0x3D18  PpabAmount       (ULONG, mW)  ← 动态功耗预留
                 ├─ +0x3D20  LowerBoundary    (ULONG, mW)  ← 下限
                 ├─ +0x3D24  UpperBoundary    (ULONG, mW)  ← 上限（60W 墙）
                 └─ Board Object
                      ├─ +0x104  Selector2 (MAX)   {Mode, Count, Effective, Source[]}
                      └─ +0x1F4  Selector3 (CURRENT) {Mode, Count, Effective, Source[]}
```

### 4.2 三个厂商内部函数

| 函数 | RVA（本机 617.42） | 签名 | 作用 |
|---|---|---|---|
| `BoardSet` | `0x8D7080` | `(Major, Root, Board, Selector, Source, Value)` | 设置某个 selector 的某个 source |
| `SetAmount` | `0x4E4D90` | `(Major, Amount)` | 设置动态功耗预留量 |
| `SetEligibility` | `0x4E4E00` | `(Major, Eligible)` | 使能/禁用功耗调节 |

### 4.3 写入流程（三阶段）

```
PHASE A  StageTargetAtStockCeiling()
  ├─ BoardSet(MAX, FE, Stock)        把 MAX 复位到原厂值
  ├─ write Root+0x3D24 = Stock       恢复上限
  ├─ write Root+0x3D14 = base        设置核心目标 = Target - amount
  ├─ SetAmount(amount)               设置动态预留
  └─ SetEligibility(1)               使能

PHASE B  CallBoardSet(MAX, FE, Target)  直接写目标值

PHASE C  原生 generator 重跑 + 读回校验
  └─ 失败则 RestoreContextToBaseline() 自动回滚
```

### 4.4 状态机

```
Unknown(0) → Armed(1) → Applied(2)
                   ↓
          StockBaseline(9)  ← 原厂一致状态，写入的前提
          ContextInvalid(7) ← 结构解析失败
          Mixed(3) / PreconditionNotReady(8)
```

---

## 5. 工具链搭建

### 5.1 编译器（MSVC）

本机已装 **Visual Studio Build Tools 18**（`C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`），但**只含 MSBuild 工作负载，缺 C++ 工具集**。

补装命令（注意：`--wait` 是 bootstrapper 的参数，`setup.exe modify` 不接受）：

```cmd
"C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify ^
    --installPath "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools" ^
    --add Microsoft.VisualStudio.Workload.VCTools ^
    --includeRecommended --quiet --norestart --nocache
```

装完得到 `VC\Tools\MSVC\14.51.36231`，编译器版本 **19.51.36260**。

### 5.2 WDK 与 SDK（无需单独安装）

`build.ps1` 的 `ensure-dependencies.ps1` 会从 NuGet 拉取三个包。若自动拉取失败，可手动下载并解压到 `-PackagesRoot` 指定目录，布局要求：

```
<PackagesRoot>/
  microsoft.windows.wdk.x64/10.0.26100.6584/c/{Include,Lib}/10.0.26100.0/km/...
  microsoft.windows.sdk.cpp/10.0.26100.6584/c/Include/10.0.26100.0/{um,shared,ucrt}/
  microsoft.windows.sdk.cpp.x64/10.0.26100.6584/c/{um,ucrt}/x64/*.lib
```

下载地址：`https://api.nuget.org/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg`

### 5.3 源码目录结构（关键）

`build.ps1` 的 `$PSScriptRoot` 已指向源码根目录，它内部再拼 `src\driver\...`。**必须是三层结构**：

```
<源码根>/
  build.ps1
  build.cmd
  tools/
    check-capstone.py
    adapt.py
    discover.py
    signatures.py
    anchors.py
    compile.ps1
    ensure-dependencies.ps1
  src/
    driver/driver.c
    driver/nvpwr_target.h   ← 由 adapt.py 自动生成
    cli/nvpwrctl.cpp
    shared/nvpwr_ioctl.h
```

平铺文件会导致 `缺少依赖检查脚本` 错误。

### 5.4 capstone 版本（严格）

`check-capstone.py` 要求 **精确 5.0.6**：

```bash
pip install capstone==5.0.6 -i https://mirrors.aliyun.com/pypi/simple/
pip install pefile==2024.8.26
```

PyPI 直连无 5.0.6，必须走镜像。5.0.7 会被拒绝。

### 5.5 构建命令

```cmd
build.cmd ^
    -Python "<venv>\Scripts\python.exe" ^
    -PackagesRoot "<deps>\packages" ^
    -NoInstallDependencies ^
    -OutputDirectory "<out>"
```

注意：**输出目录必须不存在**（`build.ps1` 拒绝覆盖）。

`build.ps1` 会自动重跑 `adapt.py`，为**本机驱动**重新生成 `nvpwr_target.h`——这是关键，它让 RVA 自动匹配当前驱动版本。

---

## 6. 源码适配：三处关键改动

原始代码来自 `全驱动均可解锁.zip` 的 `src/driver/driver.c`。

### 改动 1：F7/cTGP 缺失从致命降级为记录

**位置**：`FillStatusFromContext()`，原 line 540

```c
/* 原始 */
if (Out->CurrentF7Value == INVALID_POWER) {
    Out->State = NvpwrStateContextInvalid;
    Out->Detail = NvpwrDetailSelector3F7;
    Out->LastNtStatus = STATUS_NOT_FOUND;
    return;                                    // ← 直接失败
}

/* 改为 */
if (Out->CurrentF7Value == INVALID_POWER) {
    NVPWR_LOG_INFO("FillStatusFromContext: selector3 F7 source absent on this KMD; continuing without it\n");
}
```

**原因**：GA107 的 board「current」槽在 stock 状态下不发布 F7 源（读作 `0xFFFFFFFF`），但 armed 后能被写入路径正常填充。**重要修正**：这不是「结构性缺失」，而是「stock 状态下惰性未激活」。

### 改动 2：StockBaseline 门槛放宽

**位置**：约 line 638

```c
/* 原始：硬编码 100W–200W */
if (Out->UpperBoundary >= 100000u && Out->UpperBoundary <= 200000u &&
    Out->MaxEffective == Out->UpperBoundary &&
    Out->MaxSource0Value == Out->UpperBoundary &&
    Out->RootInitialized == 1 &&
    Out->Eligibility == 0 &&
    Out->AmountActive == 0 &&
    Out->CtgpTarget == Out->UpperBoundary &&
    Out->PpabAmount == 0 &&
    Out->LowerBoundary < Out->UpperBoundary &&          ← 改动点 2a
    Out->CurrentF7Value == Out->UpperBoundary &&        ← 改动点 2b
    Out->CurrentEffective == Out->UpperBoundary) {

/* 改为 */
if (Out->UpperBoundary >= POWER_ABSOLUTE_MIN && Out->UpperBoundary <= POWER_ABSOLUTE_MAX &&
    (Out->UpperBoundary % POWER_STEP) == 0 &&
    Out->MaxEffective == Out->UpperBoundary &&
    Out->MaxSource0Value == Out->UpperBoundary &&
    Out->RootInitialized == 1 &&
    Out->Eligibility == 0 &&
    Out->AmountActive == 0 &&
    (Out->CtgpTarget == Out->UpperBoundary || Out->CtgpTarget == INVALID_POWER) &&
    Out->PpabAmount == 0 &&
    (Out->LowerBoundary < Out->UpperBoundary ||
     Out->LowerBoundary == Out->UpperBoundary ||
     Out->LowerBoundary == INVALID_POWER) &&            ← 放宽：接受相等
    (Out->CurrentF7Value == Out->UpperBoundary ||
     Out->CurrentF7Value == INVALID_POWER) &&          ← 放宽：接受缺失
    Out->CurrentEffective == Out->UpperBoundary) {
```

**关键发现**：GA107 的 `LowerBoundary == UpperBoundary == 60000`（OEM 锁死功耗区间）。原判据要求严格小于，导致永远无法进入 StockBaseline。

### 改动 3：动态预算按实际余量计算（最关键）

**新增函数**（放在所有宏与 typedef 之后，约 line 91）：

```c
#define PPAB_FIXED  25000u   /* 原始硬编码 25W */

static __forceinline ULONG ResolvePpabAmount(PVOID Root)
{
    volatile ULONG *upper, *lower;
    ULONG headroom;
    if (!Root) return 0;
    upper = (volatile ULONG *)((PUCHAR)Root + OFF_ROOT_UPPER);
    lower = (volatile ULONG *)((PUCHAR)Root + OFF_ROOT_LOWER);
    __try {
        if (*upper == 0 || *upper <= *lower) return 0;   /* 锁死 → 预算 0 */
        headroom = *upper - *lower;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return (headroom < PPAB_FIXED) ? headroom : PPAB_FIXED;
}
```

**Phase A 修改**：

```c
/* 原始 */
base = Target - PPAB_FIXED;
CallSetAmount(Ctx, PPAB_FIXED);

/* 改为 */
amount = ResolvePpabAmount(Ctx->Root);
base = (amount <= Target) ? (Target - amount) : 0;
CallSetAmount(Ctx, amount);
```

**为什么必须改**：反汇编 `nvlddmkm.sys` 的 `SetAmount`（RVA `0x4E4D90`）发现厂商真实校验：

```asm
004E4DB1  mov edx, [rax+0x3D24]    ; Upper = 60000
004E4DB7  mov r9d, [rax+0x3D20]    ; Lower = 60000
004E4DBE  cmp edx, r9d            ; ecx = Upper - Lower = 0
004E4DC1  jb  0x4e4de2            ; 0 < Amount(25000) → 拒绝
...
004E4DF5  mov eax, 0x1f           ; 返回 31 = ERROR_GEN_FAILURE
```

厂商要求 `Amount ≤ Upper − Lower`，而本机该值为 **0**，硬编码的 25000 必然被拒 → `Set failed: Win32=31`。

**配套调整**：Armed / Applied 判定需接受 `PpabAmount == 0`（此时 CtgpTarget 承载全部目标）：

```c
/* Applied 判定 */
((Out->PpabAmount == PPAB_FIXED && Out->AmountActive == 1 &&
  Out->CtgpTarget == (Out->UpperBoundary - PPAB_FIXED)) ||
 (Out->PpabAmount == 0 && Out->CtgpTarget == Out->UpperBoundary))

/* Armed 判定的 AppliedTarget 计算 */
Out->AppliedTarget = (Out->CtgpTarget != INVALID_POWER)
    ? (Out->CtgpTarget + (Out->PpabAmount <= PPAB_FIXED ? Out->PpabAmount : 0))
    : 0;
```

---

## 7. 驱动签名与加载

### 7.1 为什么用测试签名而不用 KDU

**KDU 路线在本机失败**：

| KDU provider | BugCheck | 原因 |
|---|---|---|
| Intel NalDrv (#0) | `0x3B` 访问违例 | 漏洞利用失败，GPU 侧 Falcon HALT |
| Dell DBUtilDrv2 (#20) | `0xBE` NX 内存执行 | Tiger Lake 的 Intel CET 拦截 shellcode |

**测试签名路线**（最终采用）：自签证书 + `bcdedit /set testsigning on`，**完全不碰内核漏洞利用，零蓝屏风险**。

### 7.2 签名流程

```powershell
# 1. 创建自签证书（Code Signing EKU）
$cert = New-SelfSignedCertificate -Subject 'CN=NvpwrTestCert' -Type CodeSigningCert `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(9) `
    -KeyExportPolicy Exportable -KeyUsage DigitalSignature `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')

# 2. 导出并装入本机信任库（用 .NET API 避免弹窗）
$cerPath = 'C:\NvpwrCtrl\NvpwrTestCert.cer'
Export-Certificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath $cerPath -Force
foreach ($s in @('Root','TrustedPublisher')) {
    $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, 'LocalMachine')
    $st.Open('ReadWrite'); $st.Add($cert); $st.Close()
}

# 3. 签名驱动（SHA256 嵌入签名，+1408 字节）
Set-AuthenticodeSignature -FilePath 'C:\NvpwrCtrl\Nvpwr.sys' -Certificate $cert -HashAlgorithm SHA256

# 4. 启用测试模式（需重启生效）
bcdedit /set testsigning on
```

### 7.3 加载

```cmd
sc.exe create Nvpwr type= kernel start= demand binPath= "C:\NvpwrCtrl\Nvpwr.sys"
sc.exe start Nvpwr
```

`start= demand` 表示按需加载——`NvpwrCtl` 打开 `\\.\Nvpwr` 时才真正加载。

### 7.4 ⚠️ 关键限制：不支持连续改档

**必须在 `STOCK_BASELINE` 状态下一次性设置**。原因在 `SetPowerTarget`：

```c
/* PHASE A 第一步总是先复位到 Stock */
nv = CallBoardSet(Ctx, SELECTOR_MAX, SOURCE_FE, Stock);   // Stock = g_SavedUpper24 = 60000
```

- 从原厂态首次设置：Stock 恰好等于原厂值 → 正常
- 已改档状态二次改档：复位动作与新目标写入冲突 → `Win32=31`

**正确流程**：`restore` → 校验 `STOCK_BASELINE` → `set unlimited <N>`

另一处缺陷：`RestoreSavedRoot()` 只还原 `UPPER/CTGP/AMOUNT/ELIG/AMOUNT_ACTIVE`，**漏了 `LowerBoundary`**。

---

## 8. 实测性能数据

测试方法：PyTorch FP16 8192² matmul 循环（`llm_inference` 环境，RTX 3050 Ti 实测可达 17-18 TFLOPS 峰值），每 15 秒采样。

### 8.1 四档对比

| 指标 | 60W 原厂 | 70W | 85W | 90W |
|---|---|---|---|---|
| 功耗上限 | 60 W | 70 W | 85 W | 90 W |
| **实测功耗** | 59.70 | 69.57 | 76.43 | **77.82 W** |
| 核心频率(均) | ~1700 MHz | 1740 | 1860 | **1887 MHz** |
| 核心频率(峰) | 1710 | 1822 | 1897 | **1950 MHz** |
| **算力** | 16.86 TFLOPS | 17.56 | 18.00 | **18.03 TFLOPS** |
| 温度(终) | 49°C | 66 | 70 | **71°C** |
| 显存频率 | 6001 MHz | 6001 | 6001 | 6001 |

### 8.2 相对 60W 的累计增益

| 档位 | 功耗 | 核心频率 | 算力 |
|---|---|---|---|
| 70W | +16.5% | +2.4% | +4.2% |
| **85W** | **+28.0%** | **+9.4%** | **+6.8%** |
| 90W | +30.4% | +11.0% | +6.9% |

### 8.3 边际收益递减

| 区间 | 上限提升 | 算力增益 | 温度 |
|---|---|---|---|
| 60→70W | +16.7% | +4.2% | +17°C |
| 70→85W | +21.4% | +2.5% | +4°C |
| **85→90W** | +5.9% | **+0.2%** | +1°C |

### 8.4 硬件天花板判定

**85W 实际只吃到 76.43W（利用率 89.9%），90W 只吃到 77.82W（利用率 86.5%）** —— GPU 自身在约 78W 就吃不下更多，90W 的 12W 余量完全没用上。

全程（420 秒）频率 1867–1950 MHz **无持续下滑**，温度稳定 71–72°C，**未出现 thermal throttling**。

### 8.5 结论

- **85W 是性价比最优点**：算力 +6.8%，温度 +21°C
- 90W 仅峰值频率 +2.8%，适合短时爆发
- 真正的瓶颈是**散热**，不是功耗墙

---

## 9. 完整操作手册

### 9.1 日常使用（三档切换）

| 需求 | 双击运行 |
|---|---|
| 设为 70W（最凉快） | `E:\set-70w.cmd` |
| **设为 85W（推荐）** | `E:\set-85w.cmd` |
| 设为 90W（峰值频率） | `E:\set-90w.cmd` |
| **回退原厂 60W** | `E:\restore-60w.cmd` |

每个脚本都会 UAC 提权 → `restore` 回原厂 → 设置目标 → 验证 `nvidia-smi` 读数。

### 9.2 开机自动应用 85W

**只需运行一次**：

```
E:\install-boot-85w.cmd
```

它注册一个登录触发的计划任务 `NvpwrApply85W`（最高权限，允许电池供电运行），每次开机自动执行 `restore` + `set 85W`。

**验证**：

```cmd
schtasks /Query /TN NvpwrApply85W /V /FO LIST
```

**卸载**：

```cmd
schtasks /Delete /TN NvpwrApply85W /F
```

### 9.3 命令行直接操作

```cmd
C:\NvpwrCtrl\NvpwrCtl.exe status                :: 查看状态
C:\NvpwrCtrl\NvpwrCtl.exe restore               :: 恢复原厂 60W
C:\NvpwrCtrl\NvpwrCtl.exe set unlimited 85      :: 设置 85W（须在 STOCK_BASELINE 状态）
```

### 9.4 状态解读

```
State : STOCK_BASELINE (9)   ← 原厂一致，可写入
State : APPLIED (2)          ← 已设置成功，Applied target 显示当前值
State : CONTEXT_INVALID (7)  ← 结构解析失败，检查驱动版本匹配
State : MIXED (3)            ← 部分不变量不满足，需排查
```

关键字段：

```
OEM baseline     始终显示原厂值（本机 60000），回滚的依据
Applied target   当前生效的目标值
UPPER (saturation) 功耗上限
F7 input (cTGP)  核心目标功耗
Flags init/elig/amt  RootInitialized / Eligibility / AmountActive
```

### 9.5 回退与清理

**仅回退功耗**（保留驱动，可随时再设）：

```cmd
E:\restore-60w.cmd
```

**完全清理**（卸载驱动 + 关闭测试模式）：

```powershell
C:\NvpwrCtrl\NvpwrCtl.exe restore
sc.exe delete Nvpwr
bcdedit /set testsigning off    # 清除桌面水印，需重启
```

> ⚠️ 关闭测试模式后自签驱动将无法加载，需重新开启并重启。

---

## 10. 已知限制与踩坑记录

### 10.1 驱动层限制

| 限制 | 说明 | 规避 |
|---|---|---|
| 不支持连续改档 | PHASE A 总是先复位到 Stock | 每次改档前先 `restore` |
| `RestoreSavedRoot` 漏还原 LowerBoundary | 回滚不完整 | 无实际影响（该字段原本也不变） |
| 设置是内存态 | 重启/驱动卸载失效 | 用计划任务 |
| 依赖驱动版本精确匹配 | PE 身份校验 | 升级驱动后需重跑 `adapt.py` 重编 |

### 10.2 环境踩坑

| 问题 | 原因 | 解决 |
|---|---|---|
| `Option 'wait' is unknown` | `--wait` 是 bootstrapper 参数，`setup.exe modify` 不接受 | 去掉该参数，改为轮询进程 |
| `缺少依赖检查脚本` | 源码目录结构不对 | 必须三层结构 |
| `error C2065: PPAB_FIXED 未定义` | 辅助函数插在宏定义之前 | 放到所有宏和 typedef 之后 |
| capstone 版本被拒 | 5.0.7 ≠ 5.0.6 | 阿里云镜像装 5.0.6 |
| 日志被截断 | cmd 的 `>>` 独占句柄，嵌套 PS1 写同一文件失败 | 嵌套脚本写自己的日志 |
| `Set-Process failed: 字典关键字重复` | 环境同时有 `HTTP_PROXY` 和 `http_proxy` | 该上下文避免用 Start-Process |
| `nvidia-smi --format=csv,noheader` 不识别 | 本机版本不支持 `noheader` | 用 `--format=csv` |
| 任务管理器看不到 GPU 负载 | 默认显示核显引擎 | 切换到 GPU 1 / Compute_0 |
| Bash 里验证 cl 编译失败 | PortableGit 把 `/nologo` 当路径展开 | 用 PowerShell 工具验证编译 |

### 10.3 反汇编工具链

```bash
pip install capstone==5.0.6 pefile -i https://mirrors.aliyun.com/pypi/simple/
```

分析 nvlddmkm.sys 的常用流程：

```python
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE('nvlddmkm.sys', fast_load=True)
off = pe.get_offset_from_rva(0x4E4D90)
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(data[off:off+120], 0x4E4D90):
    print('%08X %-36s %s' % (ins.address, ins.mnemonic+' '+ins.op_str, ins.bytes.hex()))
```

---

## 11. 文件清单

### 11.1 日常工具（`E:\NvwrTools\` 与 `E:\`）

```
apply_power.ps1          核心脚本（-Watts 70|85|90）
restore_power.ps1        恢复原厂 + 可选关闭测试模式
install_boottask.ps1     注册开机自动应用计划任务
set-70w.cmd              设为 70W
set-85w.cmd              设为 85W（推荐）
set-90w.cmd              设为 90W
restore-60w.cmd          回退原厂 60W
install-boot-85w.cmd     一键安装开机自动 85W
```

### 11.2 驱动与工具（`C:\NvpwrCtrl\`）

```
Nvpwr.sys                自签名的定制驱动（32128 B，含签名）
Nvpwr.sys.unsigned.bak   未签名原件（30720 B）
Nvpwr.sys.unsigned.bak   备份
NvpwrTestCert.cer        自签证书
NvpwrCtl.exe             命令行工具
NvpwrTestCert.cer        证书副本
```

### 11.3 构建产物（`.workbuddy\tmp\out\output\dist\`）

```
Nvpwr.sys                编译产物（30720 B，未签名）
NvpwrCtl.exe             编译产物（143360 B）
```

### 11.4 源码与工具链（`.workbuddy\tmp\`）

```
src/                     三层结构的完整源码（已适配）
src/src/driver/driver.c  ★ 关键：含三处 GA107 适配
deps/packages/           WDK/SDK NuGet 包
nvlddmkm_copy.sys        驱动映像副本（反汇编用）
adapt_diag.json          自动发现诊断数据
probe_invariants.cpp     不变量探针源码
gpu_load.py              CUDA 负载生成器
*.log                    各阶段执行日志
```

### 11.5 关键日志（复盘证据链）

| 文件 | 内容 |
|---|---|
| `probe_final.log` | State 从 CONTEXT_INVALID → MIXED 的转折 |
| `invariants.log` | 12 条不变量逐项 PASS/FAIL，定位 LowerBoundary |
| `try70.log` | 首次 set 失败（Win32=31）+ 回滚 |
| `try85.log` | 连续改档失败证据 |
| `try85b.log` | restore→set 85W 成功 + 300s 验证 |
| `try90.log` | 90W 成功 + 420s 验证 |
| `verify70.log` | 70W 5 分钟稳定性验证 |

---

## 附录 A：技术演进时间线

```
阶段 1  调研 GitHub 项目 + 本地资产
        └─ 发现 NvpwrCtrl.zip 的预编译驱动 PE 身份匹配本机 617.42

阶段 2  KDU 路线尝试（失败 ×2）
        ├─ prv 0 (Intel NalDrv) → BugCheck 0x3B
        └─ prv 20 (DBUtilDrv2) → BugCheck 0xBE（Intel CET）

阶段 3  转向测试签名加载（成功）
        └─ 自签证书 + testsigning，驱动成功加载

阶段 4  只读探测发现三重阻塞
        ├─ 状态机硬编码 100W–200W
        ├─ board setter RVA 未确认
        └─ F7/cTGP 字段读作 0xFFFFFFFF

阶段 5  源码重编（关键突破）
        ├─ 发现 VS Build Tools 已装但缺 VCTools → 补装
        ├─ 发现 WDK 可从 NuGet 拉取 → 手动预拉
        └─ 编译成功，RVA_BOARD_TYPE0_SET=0x8D7080 内嵌

阶段 6  不变量探针定位
        └─ 12 条中 11 PASS / 1 FAIL（LowerBoundary == UpperBoundary）

阶段 7  三处源码适配 → STOCK_BASELINE 达成

阶段 8  SetAmount 闸门反汇编 → ResolvePpabAmount

阶段 9  70W / 85W / 90W 逐档验证成功
```

## 附录 B：给后续 Agent 的建议

1. **优先考虑源码适配而非二进制补丁**。编译期常量（如 `g_BoardSetConfirmed`）无法用补丁解决。
2. **用不变量探针精确定位**。不要猜哪个条件失败——写个直读 IOCTL 的程序逐项打印 PASS/FAIL。
3. **反汇编是终极工具**。厂商的校验逻辑藏在 KMD 里，`capstone` + `pefile` 5 行代码就能看清。
4. **区分「动态惰性」与「结构性缺失」**。我曾误判 F7 字段「结构性缺失」，实际是 stock 状态下不活跃，加载后正常填充。
5. **注意「先归零再设置」的写入模式**。这会导致二次改档失败。
6. **测试签名比 KDU 安全得多**。零蓝屏风险，值得优先。
7. **实测数据推翻直觉**。我曾根据 70W 数据断言「85W 无意义」，实测 85W 却带来 +6.9% 频率——不要过早下结论。

---

*文档生成时间：2026-10-16 13:05*
*所有数据均来自本机实测，日志留存于 `.workbuddy/tmp/`*