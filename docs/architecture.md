# 架构（三通道）

```
主通道: HA HACS 集成 → 本机蓝牙/ESPHome Proxy → E6 (BLE 增量抓取)
备份1: 云通道 → 瑞迈特云日报（失败兜底）+ 评分/分析报告（每日常态）
备份2: mini_agent（备用机）→ BLE 抓取 → POST 到集成 webhook（HA 超时未成功时）
```

- 数据按 `recordNo` 去重合并，实体属性带 `source`（ble/cloud/mini_ble）与抓取时间。
- 摘要 JSON 存档仅本机（0600）；HA 实体展示最新一条记录，**没有**多天聚合。
- 只读：所有写入仅限白名单（9820 state=1、官方 ACK、官方 cursor）。
- **不按治疗时段做门控**：集成每小时一轮，每轮一次有界连接（≤​60s）。设备只在请求时下发记录，
  客户端全程不写治疗/系统/时钟。

## 实体（设备名为「瑞迈特」，不展示整机型号）

| 实体 | 含义 | 单位 |
| --- | --- | --- |
| `sensor.bmc_ahi` | AHI 呼吸暂停低通气指数 | events/h |
| `sensor.bmc_treat_time_h` | 治疗时长 | h |
| `sensor.bmc_leak_avg` | 平均漏气量 | L/min |
| `sensor.bmc_epap_avg` | 平均呼气压力 EPAP | cmH2O |
| `sensor.bmc_ipap_avg` | 平均吸气压力 IPAP | cmH2O |
| `sensor.bmc_vt_avg` | 平均潮气量 | mL |
| `sensor.bmc_mv_avg` | 平均分钟通气量 | L/min |
| `sensor.bmc_rr_avg` | 平均呼吸频率 | breaths/min |
| `sensor.bmc_cloud_score` | 云端夜间评分 | — |

BLE 实体显示的是**最新一条**记录（`record_no` / `record_date` 属性可核对），所以当天未治疗时值会是 0。
名称走 HA 的 entity 翻译（`translations/en.json`、`zh-Hans.json`）。上表的 `sensor.bmc_*` 是**早期安装**的 ID；
新安装由 HA 按设备名 + 翻译名生成，不保证同样的 ID。
设备的 `hw_version` / `sw_version` 来自 GATT `0x180A` 实读（缺少时自动读一次，不硬编码）
；`model` 显式置空，因为 `0x2A24` 是蓝牙模组代号而非整机型号（见 `protocol.md`）。
