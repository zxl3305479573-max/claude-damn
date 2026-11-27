# claude-damn

Windows 上的 Claude Desktop 网络守护与多账号安全工作台（.NET 8 / WPF 原生实现，项目名与 GitHub 仓库统一为 `claude-damn`，支持 GitHub Release OTA 更新）。

## 核心能力

### 1. 内核级双层网络防护与 Fail-Closed 门禁
- **WFP 内核出站锁 + 防火墙急停双层协同**：可选启用原生 Windows Filtering Platform (`fwpuclnt.dll`) TUN-only 出站白名单（支持可选放行本机回环以兼容本地 MCP/代理；启用时会主动结束当前用户既有 Claude Desktop 进程并复核退出，避免旧连接绕过 `ALE_AUTH_CONNECT`），同时保留异常触发时的幂等防火墙阻断 + 归属校验进程树急停。
- **Fail-Closed 阻断锁定与安全启动门禁**：异常触发阻断后持续锁定状态，Claude 退出或 5 秒轻量巡检不会自动解封；阻断期间若 Claude 重新启动会再次强制终止；提供「安全启动 Claude」按钮与托盘入口，仅在未阻断且硬性环境检查全部通过时放行启动（支持 EXE 与 MSIX）。
- **单实例保护与巡检超时保护**：主程序通过互斥锁防双开（重复启动自动唤起已有窗口）；进程枚举与网络探测在后台执行，Clash TUN 命名管道诊断全程异步，WebView2 保留在界面线程并响应初始化取消。单轮检查带超时，托盘退出先停止巡检、取消并等待当前检查结束，再恢复时区与网络策略，避免检查与退出互相干扰。
- **系统代理与 TUN 路径一致性检测**：检测到系统 HTTP 代理启用时并行探测代理路径与绕过代理的 TUN 路径，面板保留两类证据并在国家或出口分歧时阻断。
- **传统 EXE 与 MSIX 双安装态兼容**：自动发现 `%LOCALAPPDATA%\AnthropicClaude`、`%LOCALAPPDATA%\Programs\Claude` 与 MSIX `WindowsApps\Claude_` 及其 `Claude-Data\<PFN>` 数据目录。
- **严格路径门禁**：代理客户端或 VPN/TUN 网卡离线时立即跳过所有外网探针（避免真实 IP 直连暴露）。
- **多代理客户端识别与多源出口兜底**：支持 `auto` / `Clash Verge` / `FlClash` / `sing-box` / `ClashX` / `Surge` / `WireGuard` / `其他 TUN`，优先识别 `198.18.*` Fake-IP TUN 与 `0.0.0.0/0` 默认路由；IPv4 出口与时区均提供多源兜底（Cloudflare → `ipinfo.io` → `ipwho.is` → `api.ip.sb`；时区支持 `ipapi.co` → `ipinfo.io` → `ipwho.is` → ICU 映射兜底）。

### 2. 23 项环境体检矩阵与地区自适应
- **核心硬检查（永不可跳过/降级）**：代理客户端、VPN/TUN 网卡、默认路由、出口 IP、IPv6 活动路由表（`::/0`、`2000::/3`、`64:ff9b::/96`）+ 强制 IPv6 出口探针、管理员助手、防火墙保护、WFP 严格模式策略。
- **策略与可选检查（支持真单项复检、按项关闭为 `Skip`、可选失败降级为 `Warn`）**：
  - Claude 进程树与活动连接端口策略（放行 TCP 443 与本机回环，非 443 远端端口告警）
  - 出口 IP 稳定性与 48 小时漂移记录（`iphistory.log`）
  - 真实 `claude.ai` DNS 解析与 Fake-IP 隧道核验
  - 原生 STUN UDP（含 `stun.cloudflare.com`、`stun.l.google.com`、`stun.miwifi.com`、`stun.chat.bilibili.com`）+ 内置 WebView2 浏览器 ICE 双层 WebRTC 检测（支持 `proxy` / `reject` 规则策略；确认非 VPN 公网泄露永不降级）
  - 出口时区自动同步与退出恢复 + 系统 Locale + Claude 客户端 `config.json` 语言检查
  - **重新适配出口地区（`set-region`）**：换国家节点后一键重新探测出口国家、时区与期望 Locale（拒绝 `CN` 出口）并同步系统时区
  - Clash Verge / FlClash 运行模式与前 16 条内核置顶规则审计（13 个 Claude 相关域名 + 3 个仅 UDP STUN 端口；FlClash 支持自动探测本机监听端口）
  - 出口 ASN 网络类型审计（`ipinfo.io` + `PeeringDB`）与 Claude HTTPS 生态可达性
  - 可插拔 4 项 IP 信誉检测（`IP 纯净度`、`IP 代理标记`、`IP 机房属性`、`IP 黑名单`，仅 HTTPS + `{ip}` 模板或 `?ip=` 参数 + `X-API-Key` 请求头 + 本地 TTL 缓存）

浏览器 ICE 收集完成、存在匹配 HTTP 出口基准的公网候选、原生 STUN 每项均成功且地址全部匹配出口时，如果仅剩 `701 / STUN host lookup received error`，并且每条错误对应的 STUN 服务也已由原生探针验证成功，WebRTC 显示非阻断警告「出口一致，存在部分 ICE 解析告警」，保留原始错误与候选证据。缺少出口基准、公网候选或原生成功结果，任一原生探针未完成，或者存在其他 ICE 错误时，仍保持未验证；发现非预期公网地址仍判失败，不能通过忽略或非关键降级放行。

浏览器探测前，普通 `stun:` 域名先通过系统 DNS 解析为地址列表，保留所有返回的 IPv4/IPv6 地址、端口与传输参数，避免浏览器对缺失地址族重复报告解析错误。`stuns:` 与 TURN URL 保持原样；DNS 失败或无结果时保留原始 URL，继续报告真实错误，不跳过检测。

### 3. 多账号事务隔离与加密快照迁移
- **A–D 账号槽位隔离切换**：Fail-Closed 环境门禁（阻断锁定或环境检查异常时拒绝切换），采用进程互斥锁、`.new`/`.previous` 暂存换位、残留恢复保护和原子指针提交，失败自动回滚；数据独立存储在 `%LOCALAPPDATA%\ClaudeDesktopGuardian\accounts`。
- **跨账号共享路径**：支持 `keep-in-workspace.txt` 白名单（自动跳过绝对路径、`..` 越界与符号链接）。
- **`.csnap` 加密快照导出/导入**：完整兼容 `claude-switcher` 的 `CSNAP001` 格式（PBKDF2-HMAC-SHA256 200,000 次迭代 + AES-256-CBC + HMAC-SHA256 先加密后认证 + 防 Zip-Slip 逐项校验解压）。

### 4. 维护工具箱、CLI 入口与脱敏诊断
- **一键修复环境**：经由已提权的管理员助手完成 DNS 缓存刷新、时区同步、仅针对泄漏非 VPN 网卡禁用 IPv6 绑定、按 Clash 模式修复 Clash Verge `Script.js`（自动识别代理组、保留已有 `main`、重启并校验 `/rules`、失败自动回滚）及清理旧 `Merge.yaml`、刷新 WFP 策略。
- **命令行入口（`ClaudeDesktopGuardian.Cli.exe`）**：复用核心库提供 `check` / `checkdetail` / `check-item` / `status` / `switch` / `set-region` / `set-client` / `get-client` / `rules-status` / `fingerprint` / `cli-info` / `open-safe` / `diagnose-proxy --proxy|--config` / `snapshot-export` / `snapshot-import`（密码经 stdin）/ `get-check-config` / `set-check-config` / `export-diagnostics`。
- **只读体检工具**：设备指纹体检（中文字体/GPU/分辨率/虚拟化特征）、Claude Code CLI 体检、独立代理传输诊断（支持 URL 或私有 JSON `--config`，不写客户端日志、不创账号状态，退出码 `0`/`1`/`2`）。
- **一次性安全隔离浏览器**：强制禁用扩展与非代理 UDP（`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`），关闭窗口自动销毁临时配置目录。
- **持久化配置与脱敏诊断包**：`%LOCALAPPDATA%\ClaudeDesktopGuardian\config.json`、512 KiB 自动轮转脱敏日志 `logs\guardian.log` 及一键导出剔除 IP/密钥的诊断 `.zip`。

## 构建与测试

需要 .NET 8 SDK。

```powershell
dotnet run --project tests\ClaudeDesktopGuardian.Tests.csproj -c Release
dotnet build src\ClaudeDesktopGuardian.Core\ClaudeDesktopGuardian.Core.csproj -c Release
dotnet build src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj -c Release
dotnet build src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj -c Release
dotnet build src\ClaudeDesktopGuardian.Cli\ClaudeDesktopGuardian.Cli.csproj -c Release
node --check src\ClaudeDesktopGuardian.App\web\webrtc\leak-check.js
```

完整发布构建（含测试、JS 语法检查与 PowerShell UTF-8 BOM/AST 校验）：

```powershell
.\build.ps1
```

测试包含独立 STA / WPF Dispatcher 回归：完整、轻量与单项检查执行期间仍能处理界面操作，WebView2 探测仍在界面线程；Clash 运行态 TUN 诊断使用随机本机测试管道验证开启、关闭、无响应超时和主动取消，不访问真实代理或修改系统设置。

### 自动更新

Guardian 启动后会只读检查 GitHub 正式 Release，也可以在窗口点「检查更新」。安装更新前会下载共享运行目录压缩包、核对 Release 的 SHA-256，并请求管理员确认；确认后先恢复时区与网络策略，再替换程序文件。更新失败会自动还原，旧程序目录作为 `.rollback.<事务号>` 保留；账号存档、配置与运行状态位于用户数据目录，不随 OTA 替换。发布使用 `guardian-vMAJOR.MINOR.PATCH` 标签触发 `.github/workflows/guardian-release.yml`，CI 生成包含 App、Helper、CLI、共享运行时与更新器的 Windows x64 zip 和 SHA-256 清单。

若旧版卡在检查且重复打开仍无响应，单实例机制会继续唤起同一个旧进程。更新时需先结束旧实例，再启动修复版本；仅打开另一个目录的 EXE 不会切换到新版本。维护者部署前保留原安装目录的备份，需要回滚时退出新版并还原备份；本次修复不迁移账号或配置格式。

## 安装与卸载

### Claude 仅走 TUN，同时保留系统代理

Guardian 的「安全启动 Claude」及切换账号后的自动启动会传入 Electron 支持的 `--no-proxy-server`，使 Claude 绕过 Windows 系统代理，由 TUN 接管连接。传统 EXE 使用独立进程启动参数，MSIX 使用 Windows 应用激活接口传参；传统 EXE 的子进程还会移除继承的 HTTP/HTTPS/ALL_PROXY 环境变量，不修改系统代理或其他应用环境。Codex 等应用可以继续使用系统代理。

要求严格限定虚拟网卡时，启用 WFP 严格模式并保持「允许本机回环」关闭。启动参数负责绕过代理，WFP 负责拦截非指定 TUN 的连接，两者不能相互替代。启动前须先完全退出 Claude；已有实例会拒绝启动，防止单实例转发导致参数不生效。请通过 Guardian 启动；从原快捷方式或自动启动进入的 Claude 不会自动获得该参数，严格 WFP 会继续阻止它连接本机代理。TUN 之后的代理节点选择仍由 Clash 规则决定。

验证时保留系统代理开启，确认 Claude 主进程含 `--no-proxy-server`、WFP 显示拦截直连与回环，并在 Claude 界面验证加载及消息发送。隔离测试只能证明启动参数和环境隔离，不能替代客户端联网与断开 TUN 后的真机阻断验证。回滚可还原更新前的 Guardian 安装备份，系统代理和账号格式无需迁移。

正式运行需要系统安装 Microsoft Edge WebView2 Runtime。`build.ps1` 会将 `App.exe`、`Helper.exe` 与 `Cli.exe` 发布到同一 `publish\win-x64` 目录共享单份 .NET 8 运行时（总体积约 164 MB）。使用管理员 PowerShell 安装或卸载：

```powershell
# 默认安装到 D:\Apps\claude-damn（支持 -InstallDir 自定义磁盘路径）
.\install.ps1
.\install.ps1 -InstallDir D:\Apps\claude-damn

# 卸载（先通过 Helper --cleanup-all 清理 WFP、防火墙规则并恢复临时时区，保留用户账号存档）
.\install.ps1 -Uninstall
.\install.ps1 -Uninstall -InstallDir D:\Apps\claude-damn
```

开发阶段可以先启动管理员助手，再启动 WPF 主程序：

```powershell
dotnet run --project src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj
dotnet run --project src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj
```

点击窗口右上角关闭会隐藏到系统托盘；请从托盘菜单选择“退出并恢复时区与网络策略”以干净恢复原 Windows 时区、清理 claude-damn 防火墙规则并移除 WFP 出站锁。
