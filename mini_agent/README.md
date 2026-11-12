# mini_agent — 备用机备份抓取 agent

当 HA 侧（HACS 集成）超过 `backup_after_hours` 仍未成功抓取时，本脚本在备用机上通过 BLE
抓取摘要，并 POST 到集成 webhook（按 recordNo 去重）。使用与集成相同的协议包。

## 配置（本地 `config.json`，0600，**不要提交**）

```json
{
  "target_name": "BMC_<serial>",
  "pem_path": "/secure/path/protocol_rsa.pem",
  "ha_webhook_url": "http://<ha-host>:8123/api/webhook/bmc_e6_push",
  "cursor_file": "/secure/path/mini-cursor.json",
  "push_secret": "<与集成配置里填的推送密钥一致>",
  "backup_after_hours": 2
}
```

- 协议 PEM 由你本机从官方 APK 提取（见 `../tools/`），绝不入库。
- `push_secret` 必填：webhook 默认关闭，未配置密钥时集成一律返回 403；
  GET 健康检查与 POST 推送都用 `Authorization: Bearer <push_secret>`。
- 抓取存档写入 `archive/`（0600），只存本机。
- 该脚本单次执行，无常驻进程、不自带调度，由外部计划任务（launchd / systemd timer / cron）触发。
  每次运行先 GET 同一 webhook（带 `target_name`）查询 HA 最近成功时间，未超过
  `backup_after_hours`（默认 2 小时）则跳过，避免与 HA 的连接重叠。

## 运行

```sh
python3 agent.py /secure/path/config.json
```

依赖：`bleak`、`cryptography`（建议独立 venv）。
