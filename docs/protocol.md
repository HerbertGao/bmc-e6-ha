# BMC E5/E6 BLE 协议要点（公开脱敏版）

来源：官方 APK 1.01.03 静态分析 + E6 实机验证（2026-11-11，GATT 枚举 2026-11-12）。不含密钥/SN。

## GATT 服务表（E6 实机枚举，MTU 103）

| 服务 | 特征 | 属性 | 用途 |
| --- | --- | --- | --- |
| `00001800` 通用访问 | `00002a00` | read | 设备名 = `BMC_E6<SN>` |
| | `00002a01` | read | Appearance（`0x0000`） |
| | `00002a04` | read | 首选连接参数（`ffffffff0000ffff`） |
| | `00002aa6` | read | 中央地址解析（`01`） |
| `00001801` 通用属性 | `00002a05` | indicate | Service Changed，只通知不可读 |
| `0000fe60` 厂商服务 | `0000fe61` | write, write-no-rsp | 未使用 |
| | `0000fe62` | notify | 未使用 |
| | `0000fe63` | write, write-no-rsp, notify | 未使用 |
| | `0000fe64` | write, write-no-rsp, notify | 认证与全部数据收发 |
| `0000180a` 设备信息 | `00002a24` | read | `L-BTMSB95-G0SC4` |
| | `00002a26` | read | `Rev01` |
| | `00002a28` | read | `v3.1.Apr 14 2023` |

要点：

- **型号靠名字、不靠特征**。`0x2A24` 是蓝牙模组代号，不是整机型号；`0x180A` 里也没有序列号（`0x2A25`）
  和厂商名（`0x2A29`）。区分 E5/E6 只能看名称前缀 `BMC_E5`/`BMC_E6`。
- `0x2A00` 与广播名同源，所以**连接后也能读到型号前缀**，不必依赖广播里是否有名字。
- FE60 只有 `fe64` 参与自有协议；`fe61`/`fe62`/`fe63` 属性为写/通知，**不可读**，本集成不使用。
- 集成把 `0x2A24`→`hw_version`、`0x2A28`→`sw_version`，仅在缺失时读一次并持久化。

## 代理侧调用注意（ESPHome Bluetooth Proxy）

用 `aioesphomeapi` 直接驱动代理时有三个坑，否则连接请求会毫无响应地超时：

1. 先 `subscribe_bluetooth_le_raw_advertisements` 和 `subscribe_bluetooth_connections_free`，扫描器才会运行；
2. `bluetooth_device_connect` 必须 `await`（返回的是解绑回调）；
3. `feature_flags` 要显式传入设备上报值（E6 代理为 `0xFF`），默认 0 会误报不支持 `REMOTE_CACHING`。

## 传输与认证

- GATT：服务 `0000fe60`，特征 `0000fe64`（notify + write + write-without-response）承载全部收发；完整服务表见上。
- 广播：16-bit FE60 + 厂商 ID 682 + 名称 `BMC_<SN>`。
- 帧：`start=2`，`algorithm`（认证=1 RSA，认证后=5 AES），CRC-16/XMODEM。
- 认证后加密：AES-192-CBC，IV=全 0，PKCS7。
- GATT 写：20 字节 Write Request 分片（整帧 132 字节直写会失败）。
- 逻辑命令 → 线号：`(logical + 23460) & 0xFFFF`。
- 认证：VERIFY_SERVER（挑战 num1+1/num2-1、param1=1）→ CONFIRM_KEY（24 字节 AES 密钥，alg=1）
  → CONFIRM_KEY_REPLY（alg=5，解密+CRC 后 command==3 即成功）。

## 每日读取流程（已验证）

认证 → 一次 9772（回 33233 param1=1）→ 1700/1702/1704/1720 ACK + 一次空 queryWorkState（23172）
→ 1406/1412/1416 ACK → **1416 后主动 9820 state=1**（官方 Dart 手动同步路径）
→ 设备回 33281、1092 → 回 **1093 cursor**（官方规则：空库 0；否则最大完整 recordNo，BE uint32）
→ 1030 摘要 / 1090 结束 / 事件分片（1032–1082、1108–1114，全部 N+1 ACK）。
心跳：wire 8 空载荷，T+10s 起每 10s，设备回 wire 9 空 ACK（纯保活）。
增量：1093 回 N → 设备从 N+1 续推；N 为最新时重推最新一条，无新 1030 即读完。
**1520 弹窗范围推送非必需**（官方自动路径才用，主动路径不需要）。

## 单位（已与官方 App 核对）

AHI/ODI 族 ÷10；漏气 ÷10 L/min；压力 ÷100 cmH₂O；分钟通气量 ÷1000 L/min；
时间（runTime/treatTime）秒；潮气量 mL；呼吸频率 次/分。
日期字段按 BMCTime/NewSummaryInfo（year=byte+1900、小时原值、ms uint16 LE）。

## 每日汇总字段对照（NewSummaryInfo）

一帧摘要的载荷按固定顺序排列，全部整数为**小端**；字符串为定长 UTF-8，尾部 NUL 填充。
「依据」列说明换算的确认方式：*App* = 与官方 App 界面数值逐条比对；
*一致性* = 字段之间的比例关系自洽（例如分项之和等于总时长）；*未证实* = 只在实机出现过，
单位尚不能确定，集成按原始值透出，不做换算。

### 头部与时间

| 字段 | 类型 | 单位/换算 | 依据 |
| --- | --- | --- | --- |
| `headFlag` `size` | u16 | 帧标识与声明长度，非数据 | — |
| `mainVer` `subVer` | u8 | 记录格式版本 | — |
| `headRev` | 2B | 版本字符串 | — |
| `recordDate` | 8B | year=byte+1900、month、day、hour、minute、second、ms uint16 LE | App |
| `recordNo` | u32 | 记录序号，无单位 | App |
| `runTime` | u32 | 秒，设备本次通电运行时长 | App |
| `treatTime` | u32 | 秒，治疗时长（24191 = 6.72 h） | App |
| `leakTime` | u32 | 秒，漏气相关累计时长 | 未证实 |
| `spo2Time` | u32 | 秒，血氧有效记录时长（4753 = 79.2 min） | 一致性 |
| `treatCnt` | u16 | 次，治疗次数 | App |
| `firstMode` `lastMode` | u8 | 模式代码，无公开枚举 | 未证实 |
| `buildTime` | u32 | 记录生成时间戳 | 未证实 |

### 压力（÷100 → cmH₂O）

| 字段 | 类型 | 实测样例 | 说明 |
| --- | --- | --- | --- |
| `initP` | u16 | 300 → 3.00 | 起始压力 |
| `epapMax` `epapAvg` `epap95` `epap50` | u16 | 956 / 691 / 900 / 700 | 呼气相最大/均值/95/50 分位 |
| `ipapMax` `ipapAvg` `ipap95` `ipap50` | u16 | 1406 / 1068 / 1300 / 1100 | 吸气相同四项 |

### 事件指数（÷10 → 次/小时）

| 字段 | 类型 | 实测样例 | 说明 |
| --- | --- | --- | --- |
| `ahi` `ai` `hi` | u16 | 20 / 15 / 5 | 总指数、呼吸暂停、低通气 |
| `oai` `cai` `uai` | u16 | 13 / 1 / 1 | 阻塞性、中枢性、未分类 |
| `ohi` `chi` `uhi` | u16 | 4 / 3 / 1 | 对应低通气三类 |
| `ahiWithCh` `hiWithCh` | u16 | 23 / 8 | 含 Cheyne-Stokes 的合并值 |
| `odi` | u16 | 0 | 氧减指数 |
| `sni` | u16 | 214 → 21.4 | 鼾声指数，按同族 ÷10 处理，未单独与 App 比对 |
| `reraIndex` | u16 | 0 | 微觉醒相关事件指数 |

### 容量、通气与漏气

| 字段 | 类型 | 单位/换算 | 实测样例 |
| --- | --- | --- | --- |
| `vtMax` `vtAvg` `vt95` `vt50` | u16 | mL，原值 | 1303 / 401 / 700 / 382 |
| `mvMax` `mvAvg` `mv95` `mv50` | u32 | ÷1000 → L/min | 20560 / 6595 / 10625 / 6429 |
| `leakMax` `leakAvg` `leak95` `leak50` | u16 | ÷10 → L/min | 167 / 71 / 140 / 60 |
| `inspTimeMax` `inspTimeAvg` `inspTime95` `inspTime50` | u16 | ÷10 → 秒 | 16 / 11 / 13 / 11 |

### 血氧与脉率

| 字段 | 类型 | 单位/换算 | 实测样例 |
| --- | --- | --- | --- |
| `spo2Max` `spo2Min` `spo2Avg` `spo295` `spo250` | u8 | %，原值 | 98 / 91 / 94 / 98 / 97 |
| `spo2Time95to100` … `spo2Time0to69` | u16 | **分钟**，7 个区间桶 | 50 / 28 / 0 / 0 / 0 / 0 / 0 |
| `prMax` `prMin` `prAvg` `pr95` `pr50` | u8 | 次/分，原值 | 90 / 64 / 77 / 89 / 77 |
| `rrMax` `rrAvg` `rr95` `rr50` | u8 | 次/分，原值 | 22 / 16 / 20 / 17 |
| `tst90` | u16 | 血氧低于 90% 的时长 | 未证实 |

血氧区间桶为**分钟**：同一条记录 7 个桶之和为 78，`spo2Time` 为 4753 秒 = 79.2 分钟，
两者在设备自身取整范围内一致。这条是"血氧只覆盖部分夜晚"的直接证据。

### 比例与睡眠分期

| 字段 | 类型 | 单位/换算 | 实测样例 |
| --- | --- | --- | --- |
| `sInspRatio` `sExpRatio` | u16 | 标度未证实 | 1000 / 1000 |
| `ieMax` `ieAvg` `ie95` `ie50` | u16 | ÷1000 → 吸呼比（0.448 即 1:2.2） | 647 / 448 / 623 / 482 |
| `sleepStageWakeTime` `sleepStageLightTime` `sleepStageDeepTime` | u16 | **×2 秒** | 948 / 7874 / 3272 |
| `sleepStageWakeCnt` | u16 | 次，觉醒次数 | 11 |
| `mouthLeakTime` `periodicTime` `mildFlowLimitTime` `moderateLimitTime` `severeLimitTime` `snoreTime` | u16 | 时长，秒/分钟未证实 | 90 / 0 / 60 / 1 / 1 / 1 |
| `hypoBurden` | u16 | 低氧负荷，标度未证实 | 3 |

睡眠分期为 **2 秒/单位**：同一条记录 948+7874+3272=12094 单位 ×2 = 24188 秒，
与 `treatTime` 24191 秒只差 3 秒（设备自身取整），因此判定成立。

### 尾部与保留区

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `reserveP` 18B、`reserveIndex` 16B、`reserve` 20B | 定长字符串 | 厂商保留，内容不参与计算 |
| `checksum` | u16 LE | 载荷校验，集成按此拒绝截断帧 |

上述"未证实"字段不影响任何已暴露的实体取值；集成对它们要么原值透出，要么完全不暴露
（清单见 `attributes.py` 的 `NOT_ATTRIBUTES`），并由 `tests/test_attributes.py` 保证
解析器新增字段必须被显式分类。

## 安全边界（重要）

厂商的“加密”是**用 App 公钥做 RSA 私钥加密**来下发会话密钥。公钥在每个 APK 里都有，
所以近场掎包者可以用它解出会话密钥，并伪造合法的 AES 帧（CRC-16 本来就可算）。

结论：**BLE 链路不具备保密性，也不提供完整性保障**。本集成的实际防护是**只读白名单**
（不写治疗/系统/时钟、不清记录、不 OTA、不枚举未知命令），而不是加密。
不要把这条链路当成隐私通道。

告警状态（wire 1406 的 AlarmState 载荷、24 个槽位表与未定义槽位）见 [`alarms.md`](alarms.md)。

## 禁止项

治疗/系统/时钟 setter（9712/9736/9756/10004/10006/9746）、clearDevice 9744、
setDefault 9742、OTA 1012/1014/1026、getSystemTime 23468；未知命令不泛化 N+1；
9820 只用 state=1，不枚举其它 state；1093 只按官方 cursor 规则。
