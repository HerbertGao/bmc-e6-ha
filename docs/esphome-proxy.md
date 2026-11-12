# ESPHome Bluetooth Proxy 接入

HA 主机的本机适配器与呼吸机之间 RSSI 约 -90，链路在连接后 5–8 秒自行断开，服务发现无法完成，
不能作为抓取通道。改用一块 ESP32 放在呼吸机旁运行 `bluetooth_proxy`，HA 通过 WiFi 让代理转发 BLE。

## 硬件要求

- **必须支持 BLE**：ESP32 或 ESP32-S3。ESP32-S2、ESP8266 没有 BLE，不可用。
- **ESPHome 官方支持**：`esp32` 或 `esp32-s3` 平台均可用。
- **供电**：USB 常供电；代理不做深度休眠，电池供电不现实。
- **天线**：板载 PCB 天线在同房间内足够；WiFi 覆盖不足时再选 IPEX 外置天线型号（对 BLE 侧无影响）。
- **数量**：一个即可，放在呼吸机 2 米内。

实测使用的板型为 ESP32-S3 开发板（ESPHome 板型 `esp32-s3-devkitc-1`）与一块经典 ESP32
（`esp32dev`），两者都能完成连接与下载。

## 固件

1. 用 Chrome 打开 <https://web.esphome.io/>，USB 连接 ESP32，先刷入 ESPHome 基础固件。
2. 在 ESPHome 中为该设备添加以下配置（WiFi 与板型按实际修改）：

```yaml
esphome:
  name: bmc-ble-proxy
esp32:
  board: esp32dev        # ESP32-S3 用 esp32-s3-devkitc-1
  framework:
    type: arduino
wifi:
  ssid: "你的WiFi"
  password: "你的密码"
api:
logger:
ota:
  - platform: esphome
esp32_ble_tracker:
  scan_parameters:
    interval: 1100ms
    window: 300ms
    active: true
bluetooth_proxy:
  active: true
```

`active: true` 是必需的：设备名位于扫描响应中，被动扫描拿不到。

3. 烧录后放在呼吸机 2 米内，USB 常供电。

## HA 接入

1. HA 的 ESPHome 集成会发现该设备；添加后，Bluetooth 集成中多出一个远程适配器。
2. 确认 `BMC_<SN>` 的广播能经该代理出现在 HA 中。
3. `bmc_e6` 集成通过 HA 蓝牙栈自动路由到该远程适配器做 bleak 连接，不需要改动网络或
   扫描模式。

首次启动时，HA 的 ESPHome 代理扫描器约 20 秒后才注册，集成此时会等待 45 秒重试一次；
开机首轮先失败再重试属预期行为。

## 验收

用一次增量下载（cursor = 最新 recordNo）验证整条链路：扫描（经代理）→ 连接 → 认证 → 摘要。
通过标准：完成认证并取得摘要，连接在 60 秒上限内保持稳定。实测 RSSI -47 ~ -61，MTU 103。

## 代理侧 API 注意事项

用 `aioesphomeapi` 直接驱动代理时有三处要求，否则连接请求会毫无响应地超时：

1. 先 `subscribe_bluetooth_le_raw_advertisements` 与 `subscribe_bluetooth_connections_free`，
   扫描器才会运行；
2. `bluetooth_device_connect` 是协程，必须 `await`（返回的是解绑回调）；
3. `feature_flags` 要显式传入设备上报值（实测代理为 `0xFF`），默认 0 会被误判为不支持
   `REMOTE_CACHING` 而直接报错。
