# Trae 每日自动签到

自动完成 TraeWork 每日签到领取积分，无需手动打开 IDE。

## 原理

1. 从 TraeWork 本地 `storage.json` 读取加密的认证信息（`iCubeAuthInfo://icube.cloudide`）
2. 使用 AES-128-CBC + SHA-512 解密提取 accessToken（Trae SG 国际版为明文 JSON，无需解密）
3. 调用签到 API 检查状态，未签到则领取积分
4. Token 过期时自动尝试刷新

## 支持版本

| 参数 | 对应 IDE | 加密 | API 端点 |
|------|----------|------|----------|
| `cn` | Trae CN 国内版 | tc 加密 | api.trae.cn |
| `solo-cn` | TRAE SOLO CN 独立部署版 | tc 加密 | api.trae.cn |
| `sg` | Trae 国际版 | 明文 JSON | a0ai-api-sg.byteintlapi.com |
| `solo-sg` | TRAE SOLO 国际版 | tc 加密 | a0ai-api-sg.byteintlapi.com |

## 安装

```bash
pip install cryptography
```

## 使用

### 手动签到

```bash
# 默认 solo-cn 版本
python3 trae_checkin.py

# 指定版本
python3 trae_checkin.py -e cn
python3 trae_checkin.py -e sg
```

### 定时任务

**macOS (launchd):**

```bash
# 创建 plist 文件
cat > ~/Library/LaunchAgents/com.trae.checkin.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.trae.checkin</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/trae_checkin.py</string>
        <string>-e</string>
        <string>solo-cn</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>9</integer>
    </dict>
</dict>
</plist>
EOF

# 加载
launchctl load ~/Library/LaunchAgents/com.trae.checkin.plist
```

**Linux (cron):**

```bash
# 每天北京时间 9:00 执行
echo "0 9 * * * /usr/bin/python3 /path/to/trae_checkin.py -e solo-cn" | crontab -
```

### 命令行参数

```
python3 trae_checkin.py [-h] [-e {cn,solo-cn,sg,solo-sg}] [--log LOG]

  -h, --help            显示帮助
  -e, --edition         Trae 版本 (默认: solo-cn)
  --log LOG             日志文件路径 (默认: ~/.trae_checkin.log)
```

## 前置条件

- 已安装并登录对应版本的 TraeWork
- Python 3.8+
- `cryptography` 库

## 安全说明

- 脚本只读取本地登录态文件，不打印、不上传 token
- 不修改 TraeWork 的任何文件
- Token 有效期约 14 天，过期后需重新打开 TraeWork 登录刷新
- 所有操作仅调用 Trae 官方 API

## tc 加密协议

Trae CN / TRAE SOLO CN / TRAE SOLO 国际版 对认证数据使用自定义 "tc" 加密：

1. Base64 解码 → `[6B Header][32B RandomKey][N Ciphertext]`
2. Header `0x74 0x63` ("tc") 标识加密类型
3. 密钥派生：`SHA-512(RandomKey)` → XOR 盐值 → `SHA-512` → Key(16B) + IV(16B)
4. AES-128-CBC 解密 → `[64B SHA-512 Hash][Plaintext JSON]`
5. 哈希验证 → 明文 `{ token, refreshToken, userId, ... }`

Trae SG 国际版例外：认证字段为明文 JSON，无需解密。

## 免责声明

本项目仅供个人学习和研究目的使用，禁止用于任何商业用途。

- 使用本项目前，请确保你的行为符合 Trae 的服务条款
- 作者不对使用本项目产生的任何后果承担责任
- 本项目不存储、不上传任何个人凭据，所有操作均在本地完成
- 如 Trae 官方认为本项目不妥，请联系作者删除

## License

MIT
