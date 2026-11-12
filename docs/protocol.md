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

## 安全边界（重要）

厂商的“加密”是**用 App 公钥做 RSA 私钥加密**来下发会话密钥。公钥在每个 APK 里都有，
所以近场掎包者可以用它解出会话密钥，并伪造合法的 AES 帧（CRC-16 本来就可算）。

结论：**BLE 链路不具备保密性，也不提供完整性保障**。本集成的实际防护是**只读白名单**
（不写治疗/系统/时钟、不清记录、不 OTA、不枚举未知命令），而不是加密。
不要把这条链路当成隐私通道。

## 禁止项

治疗/系统/时钟 setter（9712/9736/9756/10004/10006/9746）、clearDevice 9744、
setDefault 9742、OTA 1012/1014/1026、getSystemTime 23468；未知命令不泛化 N+1；
9820 只用 state=1，不枚举其它 state；1093 只按官方 cursor 规则。
