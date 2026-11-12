# 协议密钥获取（本机完成，密钥永不入库）

本集成需要 BMC 协议的 **RSA 私钥**（PKCS#1 PEM），它用于 VERIFY / CONFIRM_KEY 认证。
密钥**不随仓库分发**（法律与安全考虑），请从你**自己的官方 APK** 在本机提取。

## 为什么必须自己提取

认证用的是 RSA **私钥**（`wrap_rsa(n, d, ...)`），不是公钥。只公开公钥无法完成握手，
所以“发一个公钥给大家”并不能让别人少做一步。

而这把私钥对所有使用该 App 的 BMC 设备通用，且设备端只校验认证、没有二次授权：
持有它的人不仅能读，也能发 `9712 setWorkState`、`9744 clearDevice`、OTA 等命令。
公开分发等于向公众发放“改写附近任意瑞迈特呼吸机治疗参数”的能力，因此不随仓库发布。

## 官方 App 来源

App 由厂商公开发布，任何人都可以合法取得自己那份安装包：

- Google Play：搜索开发者 **BMC Medical Co., Ltd.**（应用 `com.bmc.resmart` / 瑞迈特健康管家）
- 厂商官网：<https://en.bmc-medical.com/>（下载页）
- 手机上已安装时，也可用 `adb shell pm path com.bmc.resmart` 找到 `base.apk` 再 `adb pull` 取回

实测版本：`1.01.03`（2026-11-11）。

## 一条命令

脚本**直接接受 APK**（会自动取出 `lib/arm64-v8a/libnative-lib.so`），也接受已解出的 `.so`：

```sh
python3 -m venv ~/.venv-bmckey && ~/.venv-bmckey/bin/pip install pycryptodome
~/.venv-bmckey/bin/python extract_protocol_key.py /path/to/base.apk --out ~/.config/bmc-e6/protocol_rsa.pem
```

完整输出如下（最后一行是自校验结果，路径随你指定而变化）：

```
source: lib/arm64-v8a/libnative-lib.so
OK: RSA-1024 PKCS#1 PEM -> /home/you/.config/bmc-e6/protocol_rsa.pem (0600)
public-key SPKI SHA-256: da8f78b41b0b33f4fe8d959bb3ef2a70f3b2ffa09723712e213d83aa00463dde
fingerprint matches the published key (com.bmc.resmart 1.01.03)
```

## 指纹校验（拿对钥匙了吗）

上面这串 `da8f78b4…463dde` 是**公钥**（SPKI DER）的 SHA-256，已用 pycryptodome 和
openssl 两种实现交叉核对。公钥哈希不泄露任何秘密，但能证明三件事：

1. 你解出来的确实是这把钥匙，而不是别的 RSA 密钥；
2. 你和别人用的是同一把钥匙（所以别人的排障结论对你也适用）；
3. **厂商是否换过钥匙**——脚本发现不一致会直接警告，这时先别粘贴，请开 issue。

自己复核（可选）：

```sh
openssl rsa -in ~/.config/bmc-e6/protocol_rsa.pem -pubout -outform DER 2>/dev/null \
  | openssl dgst -sha256
```

## 配置到 HA

把 PEM 转成单行 Base64，粘贴进集成的配置表单（密码框遮罩）：

```sh
base64 -i ~/.config/bmc-e6/protocol_rsa.pem | tr -d '\n'
```

集成在本地解码并校验 RSA-1024 后保存（仅保存在你的 HA 本地）。

## 排障

| 现象 | 原因 |
| --- | --- |
| `pycryptodome is required` | 没在装过 pycryptodome 的环境里运行（见上面的 venv） |
| `APK has no libnative-lib.so …` | 拿错了包，或这是 split APK 的 base（缺 native 库） |
| `unwrap did not yield a PEM private key` | 解包出的是 `.so` 但不含预期 blob——多半是 App 大版本变了 |
| `unexpected RSA size` | 同上，厂商换了密钥长度 |
| 集成报 `invalid_pem` | 粘贴的不是 Base64 单行 PEM，回去看上面的转换命令 |

## 原理（已验证，2026-11-11）

官方 Android 应用 `com.bmc.resmart` 的 `lib/arm64-v8a/libnative-lib.so` 内置该密钥：
密钥以 3DES-ECB 加密的 blob 存放，3DES 密钥由 native 的字符集/盐派生。解包后即得
PKCS#1 PEM（RSA-1024）。

## 禁止

- 不要把 PEM 提交到任何仓库、Issue、聊天或云盘。
- 不要把设备 SN/MAC、云 token、健康数据提交到公开渠道。
