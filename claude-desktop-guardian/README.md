# Claude Desktop Guardian

Windows 上的 Claude Desktop 网络守护程序。

当前版本提供以下基础能力：

- 识别 Claude Desktop 进程树
- 检查 VPN/TUN 虚拟网卡、默认网关、出口 IP、DNS、Claude HTTPS、原生 STUN 和浏览器 WebRTC ICE
- 持续执行轻量检查，并按配置执行完整检查
- 记录具体的异常原因
- 通过 Windows 进程事件常驻监听 Claude Desktop 启动和退出，周期检查作为兜底
- 通过管理员助手管理本程序自己的 Windows 防火墙阻断规则
- 根据出口 IP 检测 IANA 时区，启动时临时切换 Windows 时区，退出时恢复原时区
- 通过 WPF 面板查看检查数据和手动恢复状态

项目保持独立目录，当前不会修改仓库现有的 `windows/`、Orca、Docker、VPN、DNS 或 Claude 安装态。

## 构建

需要 .NET 8 SDK。

```powershell
dotnet build src\ClaudeDesktopGuardian.Core\ClaudeDesktopGuardian.Core.csproj
dotnet build src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj
dotnet build src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj
dotnet run --project tests\ClaudeDesktopGuardian.Tests.csproj
```

完整构建：

```powershell
.\build.ps1
```

## 运行

正式运行需要系统安装 Microsoft Edge WebView2 Runtime。Guardian 使用本地检测页面收集
`RTCPeerConnection` 生成的 ICE 候选，不打开外部浏览器。WebView2 缺失或初始化失败时，
浏览器 WebRTC 检查显示未验证并保持阻断。

开发阶段可以先启动管理员助手，再启动 WPF 程序。正式安装由 `install.ps1` 注册登录启动任务和管理员助手任务。

```powershell
dotnet run --project src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj
dotnet run --project src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj
```

## 状态目录

用户配置和状态保存在 `%LOCALAPPDATA%\ClaudeDesktopGuardian`。持久化日志只写脱敏摘要。面板会显示当前检查的详细数据，便于人工比较 VPN 出口、DNS、原生 STUN 和浏览器 ICE 结果。

时区临时切换状态也保存在状态文件中。程序异常结束后，下次启动会先尝试恢复原 Windows 时区。点击窗口右上角关闭只会隐藏到托盘，请从托盘选择“退出并恢复时区”结束程序。

