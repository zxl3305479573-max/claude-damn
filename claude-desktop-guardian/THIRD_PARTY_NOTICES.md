# 第三方组件说明

## `@myipscan/leak-check`

- 来源项目：MyIPScan/leak-check
- 固定版本：1.0.4
- 固定提交：`ecaf7259b6d7b9b4be4106a579dd6fd840f3a0ce`
- 许可证：MIT
- 本地文件：`src/ClaudeDesktopGuardian.App/web/webrtc/leak-check.js`
- 本地调整：改为浏览器脚本形式，增加候选地址类别和地址族字段，通过 WebView2 消息返回结构化结果。

本项目只使用该组件的浏览器端 WebRTC 候选收集逻辑。检测页面不加载其余第三方脚本，不使用远程网页和统计服务。
