# Anthropic 账号自检 Skill

这是一个面向 Claude Code 的 Codex skill，用来做 Anthropic 账号风险自检和本机环境卫生检查。

它不是“防封工具”，也不是绕过风控或地区限制的工具。它的目标是帮用户看清本机有哪些可解释、可修复、需要自己确认的风险信号，并在需要时准备诚实的整改说明或申诉材料。

## 它会检查什么

- Claude Code 相关环境变量名，但不会打印 secret 的具体值。
- Claude Code 配置和状态文件路径，以及基础文件权限。
- 当前仓库和部分 Claude Code 本地日志里疑似 key 的字符串形状。
- 代理配置，以及可选的公网出口国家和云服务商线索。
- 可选的浏览器语言、时区、GeoTime/GeoMirror 风格一致性信号。
- 已安装 Claude Code 包里的字符串证据，只作为本机证据，不直接推断服务端意图。

默认不会扫描 Claude Desktop/App 缓存。

## 它看不到什么

这个 skill 看不到 Anthropic 内部风控分、服务端封禁原因、账号创建 IP、支付历史、历史登录国家、警告邮件、申诉结果、请求级安全标记、其他设备和远程服务器上的行为。

所以它适合做“本机环境和使用习惯自检”，不能保证账号一定安全。

## 安装

在 Codex 里，可以让 skill installer 安装这个 GitHub 路径：

```text
使用 $skill-installer 安装 https://github.com/karlligamesvc-spec/anthropic-account-self-audit/tree/main/anthropic-account-self-audit
```

也可以手动克隆后复制 skill 目录：

```bash
git clone https://github.com/karlligamesvc-spec/anthropic-account-self-audit.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R anthropic-account-self-audit/anthropic-account-self-audit "${CODEX_HOME:-$HOME/.codex}/skills/"
```

安装后重启 Codex，让新 skill 被识别。

## 使用方式

对 Codex 说：

```text
使用 $anthropic-account-self-audit 分析我的 Claude Code / Anthropic 账号风险。
```

如果想检查浏览器画像一致性，可以在请求里提到浏览器语言、时区、代理、GeoTime 或 GeoMirror。

这个 skill 只有在用户明确授权后，才会执行本机低风险修改。

## 安全边界

这个 skill 用于合规自查、账号完整性检查、本机安全卫生和诚实申诉准备。不要用它绕过地区限制、掩盖违规行为、轮换账号、规避风控，或在已经被 enforcement 后继续进行不支持的使用。
