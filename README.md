# BMC E5/E6 Ventilator → Home Assistant (HACS)

本地 BLE 抓取瑞迈特（BMC）家用无创呼吸机数据，同步进 Home Assistant。
E6 已实机验证（B25A Plus）；E5 协议同源，未在任何 E5 机器上验证。

## 功能

- **主通道（本地 BLE）**：HACS 集成定时增量抓取历史摘要（治疗时长、AHI、
  漏气、压力、潮气量、通气量、呼吸频率、睡眠分期等 96 字段，单位已与官方 App 核对）。
  使用官方 `downloadNewSummary` 主动下载路径与增量 cursor，**不需要 NFC、不需要官方 App**。
  记录随 cursor 一起持久化在 HA 本地（最多保留最新 730 条），重启不丢；
  历史缺失时按 cursor 逐轮回填（每轮一次有界连接，游标前进时自动缩短间隔）。
- **云备份通道**：瑞迈特云日报作为抓取失败时的兜底；每日同步云端**评分与分析报告**
  （score/summaryTitle/summary，仅云端提供）。
- **备用机推送通道（`mini_agent`）**：HA 超过阈值未成功时，备用机通过 BLE 抓取并
  POST 到集成 webhook（按 recordNo 去重，默认关闭，需配置 `push_secret`）。

只读：不写治疗/系统/时钟、不清记录、不 OTA。健康数据仅保存在你的 HA/本机。

## 设备识别

集成匹配以下广播特征：`FE60` 服务 + 厂商 ID `682`，名称 `BMC_<SN>` 且 SN 以 `E5`/`E6` 开头。

实测注意：设备名在**扫描响应**里，部分代理/适配器会拿不到名字。此时扫描会回退到
`FE60 + 厂商 682` 找设备，**但连接后会立即读 GATT `0x2A00` 核对名称**，与配置的目标名称不一致就中止，
不会把邻居机器的记录写进本条目；若 GATT 也读不到名字且广播无名称，同样中止。
发现卡片需要广播里带名字，**没有名字时请用「手动输入名称」添加**。

**整机型号无法从蓝牙判定**：`0x180A` 的 Model Number 是蓝牙模组代号（E6 实测 `L-BTMSB95-G0SC4`），
不是 E5/E6；`0x180A` 里也没有序列号特征。区分 E5/E6 只能看名称前缀，而那是固件自报值。

## 传输：本机蓝牙基本不可用，请用 ESPHome 代理

实测本机适配器在 RSSI -90 左右会出现「连上后 5–8 秒自行断开、服务发现失败」，无法完成 GATT。
可用方案是 ESPHome `bluetooth_proxy`：集成通过 HA 的蓝牙栈自动路由到代理，无需额外配置。
代理侧调用细节与踩坑见 [`docs/protocol.md`](docs/protocol.md)。

首次启动时 HA 的 ESPHome 代理扫描器约 20 秒后才注册，集成会等 45 秒重试一次，
因此开机首轮可能先失败并自动重试，属预期行为。

## 实体

设备在 HA 中显示为「瑞迈特」，不展示整机型号；`hw_version`/`sw_version` 由 GATT `0x180A` 实读。
实体名走 HA 的 entity 翻译，实体 ID 由 HA 按设备名 + 翻译名自动生成，**不是**固定的 `bmc_*`；
升级前已存在的条目会保留原 ID。请按下面的**名称**在 UI 里辨认，不要依赖 ID。

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
| `sensor.bmc_spo2_avg` | 平均血氧饱和度 SpO2 | % |
| `sensor.bmc_spo2_min` | 最低血氧饱和度 SpO2 | % |
| `sensor.bmc_spo2_max` | 最高血氧饱和度 SpO2 | % |
| `sensor.bmc_pr_avg` | 平均脉率 | bpm |
| `sensor.bmc_spo2_time_min` | 血氧记录时长 | min |
| `sensor.bmc_cloud_score` | 云端夜间评分（属性带报告标题与摘要） | — |

### 属性

每日汇总记录的信息远多于每个指标一个数字。其余字段作为**属性**挂在对应实体上，属性名就是
协议字段名，只做单位换算（对照实测记录验证）：

| 实体 | 附加属性 |
| --- | --- |
| `bmc_ahi` | `ai` `hi` `oai` `cai` `uai` `ohi` `chi` `uhi` `hiWithCh` `ahiWithCh` `odi` `sni` `reraIndex`（次/小时） |
| `bmc_epap_avg` | `initP` `epapMax` `epap95` `epap50`（cmH2O） |
| `bmc_ipap_avg` | `ipapMax` `ipap95` `ipap50`（cmH2O） |
| `bmc_vt_avg` | `vtMax` `vt95` `vt50`（mL） |
| `bmc_mv_avg` | `mvMax` `mv95` `mv50`（L/min） |
| `bmc_leak_avg` | `leakMax` `leak95` `leak50`（L/min） |
| `bmc_rr_avg` | `rrMax` `rr95` `rr50`（次/分） |
| `bmc_spo2_avg` | `spo295` `spo250` `spo2Time95to100`…`spo2Time0to69`（分钟）`tst90` `odi` |
| `bmc_pr_avg` | `prMax` `prMin` `pr95` `pr50` |
| `bmc_treat_time_h` | `runTime` `leakTime` `leakTime40L` `sleepStageWakeTime` `sleepStageLightTime` `sleepStageDeepTime` `sleepStageWakeCnt` `inspTimeMax/Avg/95/50` `ieMax/Avg/95/50` `hypoBurden` `mildFlowLimitTime` `moderateLimitTime` `severeLimitTime` `snoreTime` `periodicTime` |

睡眠分期属性单位是分钟（设备按 2 秒为单位存储，三者之和等于治疗时长）。`ie*` 是吸呼比
（0.448 即 1:2.2）。`mildFlowLimitTime` 等时段类字段保持**设备原始数值**，秒/分钟未被证实。

每个字段的类型、单位、换算方式与确认依据（App 核对 / 内部一致性 / 未证实）见
[`docs/protocol.md` 的字段对照表](docs/protocol.md#每日汇总字段对照newsummaryinfo)。

未被暴露的解析字段只有记录头/版本/保留区/校验和，以及 `firstMode`/`lastMode`（无公开枚举）
和 `sInspRatio`/`sExpRatio`（标度未证实）。`tests/test_attributes.py` 会解析一条样本记录并与
暴露清单比对，**解析器新增字段而未分类时测试失败**，避免再次出现血氧那种漏接。

血氧只在夜间佩戴血氧探头的时段有值，`sensor.bmc_spo2_time_min` 说明这些平均值覆盖了多久
（例如治疗 6.7 小时、血氧记录 79 分钟，则 SpO2 反映的是这 79 分钟）。设备未接血氧探头时
SpO2 记录时长为 0，平均/最低/最高血氧均为 0。

BLE 实体展示**最近一条有治疗数据的记录**。设备会在日期边界提前建立下一天的记录且内容为空
（`recordDate` 固定带 `T12:00:00`，是编码产物而非真实时间）；若直接取最新记录，所有指标会显示 0，
与"AHI 为 0"无法区分，所以取值时会跳过这类空记录。

属性区分得很清楚，判断日期必须读它们，不要假设是当天：

- `record_no` / `record_date`：数值**来自**哪条记录
- `newest_record_no` / `newest_record_date`：设备当前的**最新**记录，可能仍为空
- `source`：`ble` / `cloud` / `mini_ble`

## 安装

1. HACS → 自定义仓库（Custom repositories）→ 添加本仓库（Integration 类型）。
2. 安装 "BMC E5/E6 Ventilator" 并重启 HA。
3. 从厂商公开发布的 App（Google Play 或厂商官网，见 [`tools/`](tools/README.md)）取你那份 APK，
   一条命令在本地提取协议密钥；脚本会打印公钥指纹并与已发布值比对，确认你没拿错钥匙。
4. 添加集成：蓝牙发现选择你的呼吸机（或手动输入 `BMC_<SN>`），粘贴 PEM。
   可选：配置云备份凭据（access/refresh token）。

## 云备份重新认证

云端 token 会失效（access token 8 小时，refresh token 数天，且与手机 App 共用时会被
App 的刷新挤掉）。失效后评分实体会变成 `unavailable`，并在「修复」里出现一条提示。

重新认证：**设置 → 设备与服务 → BMC E5/E6 Ventilator → 配置**，填手机号，收到短信后填验证码。
集成会自己登录并保存一对新 token，**与手机 App 各自独立**，不会再互相作废。

这一步只会发一条短信，必须手动触发——集成不会定时重登或自动重试。

## 目录

- `custom_components/bmc_e6/` — HACS 集成（config flow、coordinator、sensor、webhook）
- `custom_components/bmc_e6/bmc_ble/` — 共享 BLE 协议实现（认证/帧/摘要解析/增量下载）
- `mini_agent/` — 备用机抓取 agent（复用同一协议包）
- `tools/` — 协议密钥提取指引与脚本
- `docs/` — 协议矩阵、架构说明、告警槽位（[`docs/alarms.md`](docs/alarms.md)）
- `tests/` — 离线测试（无设备、无真实密钥）

## 隐私与安全

协议 RSA、设备 SN/MAC、云 token、健康数据**不进入本仓库**。密钥由你在本机提取并
仅保存在 HA 本地；测试使用临时生成的密钥对。详见 `docs/`。

以下三条是已知且**不会被代码修好的**边界，请如实理解：

1. **BLE 链路不具备保密性**。厂商方案用 App 公钥做 RSA 私钥加密传输会话密钥，而公钥在
   每个 APK 里都有；拿到公钥的人可在近场掎包后解开会话。集成的防护是**只读白名单**，
   不是加密。
2. **mini-agent 推送默认关闭**。未在集成配置里填写 `push_secret` 时，webhook 一律返回 403；
   填写后需以 `Authorization: Bearer <secret>` 发送，否则 401。
3. **存储权限由 HA 决定**。PEM 文件由集成以 0600 创建；但健康记录走 HA 的 `Store`，
   权限跟随 HA 配置目录的 umask，并且会进 HA 备份。

另外：多天内只保留最新 730 条记录（`RECORD_CAP`），超出部分会被删掉。

## 测试

```sh
python3 -m venv .venv && .venv/bin/pip install bleak cryptography
.venv/bin/python -m unittest discover -s tests -t tests
```

## 验证范围

在一台 E6（B25A Plus，固件通信版本见 `docs/protocol.md`）上实测通过：

- 认证与 AES 会话（RSA-1024 + AES-192-CBC）
- 历史摘要读取：recordNo 15–42 共 28 条，与官方 App 的数值逐项核对
- 增量 cursor 与回填、重启后记录恢复（Store 持久化）
- ESPHome Bluetooth Proxy 通道（MTU 103，RSSI -47 ~ -61）
- GATT `0x180A` 设备信息读取（hw/sw 版本）

未验证：E5 机型、云端通道的 token 刷新在长周期下的表现、mini_agent 的端到端推送
（该通道默认关闭，需先配置 `push_secret`）。
