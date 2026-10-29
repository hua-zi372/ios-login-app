# AGENTS.md

本项目是一个**零第三方依赖的纯原生 iOS 应用**(Swift + UIKit + WKWebView),
在 **GitHub Actions 的云端 macOS runner** 上编译出**未签名 `.ipa`**,由用户自行签名侧载。

开发机是 **Windows**,没有 Mac、没有 Apple 开发者账号。本机**不能**编译 iOS,
所有编译一律在云端进行。不要试图在本机 build。

## 重要:本项目曾是 Expo 项目,现已废弃该方案

仓库根目录仍残留 Expo/React Native 文件(`package.json`、`App.js`、`index.js`、
`app.json`、`src/`、`assets/`、`scripts/patch-expo-jsi.py`)。

**这些文件已不参与构建,是历史残留,请勿依据它们判断技术栈,也不要去修它们。**

废弃原因:Expo SDK 58 自带的 `expo-modules-jsi` 在云端 Xcode 26.3(Swift 6.2)下
编译报 `sending 'slot' risks causing data races`,连续 5 次构建失败。不要重新引入 Expo、
EAS、CocoaPods 或 React Native。需求本身用原生 3 个文件即可满足。

## 真正的源码位置

```
native/
├── project.yml                      # XcodeGen 工程定义(不提交 .xcodeproj)
├── Info.plist                       # Bundle 配置,已开启 ATS 以允许 http
└── Sources/
    ├── AppDelegate.swift            # 入口,负责登录页/网页页根控制器切换
    ├── Config.swift                 # ★ 改网址、改账号只需改这里
    ├── LoginViewController.swift    # 原生登录界面(UIKit 纯代码布局)
    └── WebViewController.swift      # WKWebView + 原生导航栏
```

`.xcodeproj` 由 CI 用 XcodeGen 现场生成,**不要手写或提交**。改工程设置请改 `project.yml`。

## 云端打包(唯一的构建方式)

工作流:`.github/workflows/build-ipa.yml`。推送到 `main` 即自动构建,
也可在 Actions 页面手动触发。产物为 artifact `ios-unsigned-ipa`。

完整流程、排错方法与已验证记录见 **[DEPLOY.md](./DEPLOY.md) —— 动手前请先读它。**

## 本机环境约束(Windows)

- Shell 是 PowerShell:用 `;` 分隔语句,**不能用 `&&`**。
- 执行策略会拦截 `npm.ps1`:如确需 node 工具链,用 `npm.cmd` / `npx.cmd`。
- git 无全局提交身份,提交必须显式传入(见 DEPLOY.md「提交与推送」)。
- 本机缓存的 git 凭据属于另一个账号,推送必须用带用户名的 remote URL(见 DEPLOY.md)。

## 修改约定

- 改功能优先只改 `native/Sources/` 下的 Swift 文件;改配置项优先只改 `Config.swift`。
- 不新增第三方依赖。零依赖是本项目构建稳定的根本原因。
- 改完必须 push 并确认云端构建 `conclusion == success` 才算完成;
  失败时用 DEPLOY.md 里的 annotations API 取真实错误,**不要盲猜或盲改**。


## 诊断版合并说明

- `native/Frameworks/` 已加入 `libwebuiopsercore.framework` 和 `SDWebuiopser.framework`。
- `native/Sources/loader89.c` 会在启动后延迟加载核心组件并写入 `Documents/loader89.log`。
- `native/Sources/Diagnostics.swift` 提供 App 内日志查看、复制、分享、上传。
- `Info.plist` 已开启文件共享，便于无越狱导出日志。
- 构建前 `project.yml` 会自动修复框架二进制可执行位。
## 89 隐藏 C2 表（已定位并改到本地）

- `SDWebuiopser` 里除 `0x13f50` 简单表外，还有第二张运行时解码常量表：
  offsets `0x14da0`、encrypted data `0x14e78`、key `0x156fa`、decoder `0xc714`。
- entry 0 原值是 `https://3e65a426.jiaoyang677.sbs`，entry 65 是 `6.66`。
  这就是旧 C2/`agentVersion=6.66` 的真实来源。
- 已用 `scripts/patch_sd_c2_table.py` 把 entry 0 改为
  `http://192.168.1.167:8080`，并恢复 `LOADER89_SKIP_CORE=0`。
