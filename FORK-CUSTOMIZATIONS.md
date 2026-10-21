# FORK-CUSTOMIZATIONS

本文件列出 `FEI352/Xboard` 相对上游 `cedar2025/Xboard` 的全部定制。
**每次从上游同步后，必须逐条重新应用并核对。**

## 1. `app/Protocols/Clash.php` — 补齐 VLESS / Hysteria2 / TUIC 协议

**问题**：上游 `Clash.php` 只处理 Shadowsocks / VMess / Trojan / SOCKS / HTTP。
Clash 客户端（Clash for Android、ClashX、Stash 等）请求订阅时，
VLESS / Hysteria2 / TUIC 节点被静默丢弃，只剩 SS 链路节点。

**改动**（+244 行）：
1. `$allowedProtocols` 增加 `TYPE_VLESS` / `TYPE_HYSTERIA` / `TYPE_TUIC`
2. `handle()` 的 `foreach` 增加三个分发分支
3. 从 `ClashMeta.php` 搬入六个方法：
   - `buildVless()` / `buildHysteria()` / `buildTuic()`
   - `appendMultiplex()` / `appendUtls()` / `appendEch()`

**验证**：
```bash
docker exec xboard-xboard-1 php -l /www/app/Protocols/Clash.php
docker exec xboard-xboard-1 grep -c 'buildVless\|buildTuic\|buildHysteria' /www/app/Protocols/Clash.php
# 期望：6
```

**上游是否已合并**：❌ 截至 `81dd561c`（2026-10-21）未合并。

## 2. `resources/views/admin/dashboard.blade.php` — 前端 UI 微调

（历史定制，2026-06 前后：礼品卡 FAB 与 BackTop 按钮重叠修复。
若上游已重构该文件，需重新核对是否仍然必要。）

## 3. 前端 UmiJS bundle — 订阅弹窗 `?flag=xxx`

（历史定制：`Dashboard` 一键订阅弹窗注入 `?flag=` 格式转换。
⚠️ 该项改的是**编译产物**，源码级改动已丢失，重建镜像后会退化。）

---

## 同步上游后的检查清单

```bash
# 1. 重置到上游
git fetch upstream master && git reset --hard upstream/master

# 2. 逐条重新应用本文件的定制

# 3. 构建并验证
docker build -t ghcr.io/fei352/xboard:$(date +%Y%m%d) .

# 4. 部署后验证节点数（Clash UA）
curl -s -A 'ClashForAndroid/2.5.12' 'https://board.fja.su/s/<token>' \
  | grep -oP 'type: \K\w+' | sort | uniq -c | sort -rn
```
