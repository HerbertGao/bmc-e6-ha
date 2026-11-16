# 告警状态：wire 1406（AlarmState）

`1406` 不是普通传输确认，而是设备推送的**告警状态列表**。官方 App 的处理方式
（`BaseNewDataProcessing.java`，case 1406）：

```
nativeCommand(-22053, 1, param2, null, 5)        // ACK，param2 回显
List<AlarmState> = AlarmState.parseFrom(payload) // 解析载荷
→ 通知 UI
```

集成只做了 ACK 那一步，载荷长期被丢弃；现在会解析并暴露（见文末）。

## 记录布局

一条记录固定 **18 字节**，一帧可含多条：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 2 | `uint16 LE` flags：bit0 = active，bit1 = confirm，bit2–15 = itemId（14 位） |
| 2 | 8 | 起始时间，BMCTime（格式见 `protocol.md`：year=byte+1900，其余原值，ms 为 uint16 LE） |
| 10 | 8 | 结束时间，BMCTime |

时间字段全 0 表示"从未触发"。`active=0` 但时间非 0 表示**曾经触发过**，窗口保留——
这是判断"最近有没有出问题"的主要依据。

## 推送形态

设备在会话早期推 3 帧，覆盖 24 个槽位（不区分是否触发过，整段推一遍）：

- 第 1 帧：101–106
- 第 2 帧：201–207
- 第 3 帧：301–310

因此一次成功会话即可拿到完整快照，不需要等告警发生。

## 槽位表

名称来自官方 App 1.01.03 的 `AlarmItem` 枚举（`number, resourceKey, detailKey`）。

| itemId | 枚举名 | 资源键 | 含义 |
| --- | --- | --- | --- |
| 101 | `kAlarmPowerFailure` | MessagesFailure | 供电故障 |
| 102 | `kAlarmDeviceFault` | MessagesFault | 设备故障 |
| 103 | `kAlarmTubeDisconnected` | MessagesDetachment | 管路脱落 |
| 104 | `kAlarmHighPressure` | MessagesHighFlow | 压力过高 |
| 105 | `kAlarmLowRR` | MessagesLowRate | 呼吸频率过低 |
| 106 | `kAlarmLowSp02` | MessagesHypoxemia | 血氧过低 |
| 201 | `kAlarmVtltLeak` | MessagesLeak | 漏气 |
| 202 | `kAlarmPowerLowVoltage` | MessagesVoltage | 电池电压低 |
| 203 | `kAlarmHeatedHumidifierFailure` | MessagesHumidifier | 加热湿化器故障 |
| 204 | `kAlarmLowPressure` | MessagesLowFlow | 压力过低 |
| 205–207 | **未定义** | — | — |
| 301 | `kAlarmLowTV` | MessagesTidal | 潮气量过低 |
| 302–304 | **未定义** | — | — |
| 305 | `kAlarmChangeMask` | MessagesMask | 需更换面罩 |
| 306 | `kAlarmCleanDevice` | Maintenance2 | 需清洁设备 |
| 307 | `kAlarmSDCardError` | MessagesInfixSD | SD 卡错误 |
| 308 | `kAlarmCheckWater` | MessagesWater | 检查水量（缺水） |
| 309 | `kAlarmCheckSp02Sensor` | SensorErr | 检查血氧探头 |
| 310 | **未定义** | — | — |

另有 `100 kAlarmNull` 与 `999 kAlarmMax` 是枚举哨兵，不作为槽位推送。

## 未定义槽位

`205`、`206`、`207`、`302`、`303`、`304`、`310` 在 1.01.03 的 Java 枚举中没有定义，
本仓库不做猜测，解析结果标为 `unknown`。

可用线索有两条：

1. **Dart 层（`libapp.so`）的告警名集合远大于 Java 枚举**，包含
   `kAlarmWaterShortageForFourHours`、`kAlarmAirSupplyFailure`、`kAlarmCompressorFailure`、
   `kAlarmFanFailure`、`kAlarmValveFailure`、`kAlarmOxygenSensorFailure`、`kAlarmOxygenAbnormality`、
   `kAlarmSDCardFull`、`kAlarmSystemOverheat` / `SystemOverheatWarning` / `SystemOvercool`、
   `kAlarmReplaceIntakeFilter`、`kAlarmChangeFilter`、`kAlarmChangeTube`、`kAlarmBreathingNotDetected`、
   `kAlarmMaskBlocked`、`kAlarmStartupDelay`、`kAlarmPressureFailure`、`kAlarmAirSupplyFailure` 等。
   这些名称多出来的部分，正是留给未定义槽位的候选。
2. **`310` 与 `308` 的起止时间几乎完全重合**（起始差约 1 秒，结束完全相同）。最合理的解释是
   `kAlarmWaterShortageForFourHours`——缺水持续满四小时触发的升级告警。**但这仍是推断**，
   代码里没有据此命名。

补全的可靠办法是取一版**更新的 APK**，从新的 `AlarmItem` 枚举一次补齐；或等某个未定义槽位
真实触发后，用它的时间窗口与已命名槽位比对。

## 集成中的暴露方式

- 解析：`bmc_ble/protocol_cmds.py:parse_alarm_states()`（纯函数，有离线测试）。
- 采集：`bmc_ble/download.py` 在 `1406` 分支里先解析载荷再 ACK。
- 快照：`coordinator` 保存最近一次快照并随状态一起持久化；**空列表不覆盖上一次**——
  空表示该会话在告警推送到达前就断开了，不代表设备没有告警。
- 实体：`binary_sensor.<device>_water_shortage`（`device_class: problem`），槽位 308 `active`
  时为开。属性给出最近一次缺水的起止时间、当前活动告警列表，以及完整的 24 槽快照。

## 只读约束

`1406` 只做 ACK，不写任何告警状态。清除告警属于设置类操作，不在本集成的白名单内。
