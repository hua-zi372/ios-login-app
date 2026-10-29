# DEPLOY.md —— 云端打包与部署手册

> 本文档是项目移交的核心。**云端打包是本项目唯一的构建方式。**
> 开发机是 Windows,没有 Mac、没有 Apple 开发者账号,本机无法编译 iOS。

---

## 0. 一句话概括

把代码 `git push` 到 GitHub 的 `main` 分支 → GitHub Actions 在云端 macOS 上
用 Xcode 编译 → 产出**未签名 `.ipa`** → 从 Actions 页面下载 → 用 Sideloadly
自行签名侧载到 iPhone。

| 项目 | 值 |
|---|---|
| 仓库 | `https://github.com/hua-zi372/ios-login-app` |
| 分支 | `main` |
| 仓库可见性 | **public(必须)** —— macOS runner 仅对 public 仓库免费 |
| 工作流文件 | `.github/workflows/build-ipa.yml` |
| 产物 artifact 名 | `ios-unsigned-ipa` |
| 产物文件名 | `LoginWebApp-unsigned.ipa` |
| Bundle ID | `com.example.loginwebapp` |

---

## 1. 技术栈(务必先看清)

**纯原生 iOS,零第三方依赖**:Swift + UIKit(登录页)+ WKWebView(网页页)。
工程文件由 [XcodeGen](https://github.com/yonaskolb/XcodeGen) 依据 `native/project.yml`
在 CI 现场生成,仓库内**不提交 `.xcodeproj`**。

```
native/
├── project.yml                      # XcodeGen 工程定义
├── Info.plist                       # Bundle 配置(已开 ATS,允许 http 网址)
└── Sources/
    ├── AppDelegate.swift            # 入口 + 根控制器切换
    ├── Config.swift                 # ★ 改网址/账号就改这个文件
    ├── LoginViewController.swift    # 原生登录界面
    └── WebViewController.swift      # WKWebView + 原生导航栏
```

### ⚠️ 根目录的 Expo 残留文件请忽略

`package.json`、`package-lock.json`、`App.js`、`index.js`、`app.json`、`src/`、
`assets/`、`scripts/patch-expo-jsi.py` 都是**已废弃的 Expo 方案残留**,
**不参与构建**。不要据此判断技术栈,也不要去修它们。

**不要重新引入 Expo / EAS / React Native / CocoaPods。** 原因见第 7 节。

---

## 2. 云端打包流程详解

工作流 `.github/workflows/build-ipa.yml` 的执行步骤:

| # | 步骤 | 做什么 |
|---|---|---|
| 1 | Checkout repository | 拉取代码(`actions/checkout@v5`) |
| 2 | Select Xcode | 选 `latest-stable` Xcode |
| 3 | Install XcodeGen | `brew install xcodegen` |
| 4 | Generate Xcode project | `xcodegen generate` 生成 `LoginWebApp.xcodeproj` |
| 5 | **Build unsigned .app** | `xcodebuild` 编译 Release/iphoneos,日志存 `build.log` |
| 6 | Extract build errors | **仅失败时**执行:把关键错误行写进 Job Summary |
| 7 | Package into unsigned .ipa | `.app` → `Payload/` → zip 成 `.ipa` |
| 8 | Upload .ipa artifact | 上传 artifact,保留 14 天 |

### 产出「未签名」包的关键参数

```bash
CODE_SIGNING_ALLOWED=NO
CODE_SIGNING_REQUIRED=NO
CODE_SIGN_IDENTITY=""
CODE_SIGN_ENTITLEMENTS=""
```

这组参数让 Xcode 跳过代码签名,因此**不需要任何 Apple 证书或开发者账号**。

### `.ipa` 的本质

`.ipa` 就是一个 zip,内部结构固定为 `Payload/<AppName>.app/`。
工作流第 7 步正是手工构造这个结构再压缩,所以不需要 `xcodebuild archive` /
`exportArchive`(那两步需要签名配置)。

### 触发方式

- **自动**:push 到 `main` 或 `master`
- **手动**:仓库 Actions 页面 → 选 "Build Unsigned iOS IPA" → Run workflow
- 同分支新推送会自动取消未完成的旧构建(`concurrency.cancel-in-progress`)

---

## 3. 下载 `.ipa`

1. 打开 `https://github.com/hua-zi372/ios-login-app/actions`
2. 点最新一次成功的构建(绿勾)
3. 页面底部 **Artifacts** → 点 `ios-unsigned-ipa` 下载(需登录 GitHub)
4. 下载到的是 zip,解压得到 `LoginWebApp-unsigned.ipa`

---

## 4. 安装到 iPhone(自行签名侧载)

未签名的 `.ipa` 不能直接装,需要用你自己的 Apple ID 重签:

1. 电脑装 [Sideloadly](https://sideloadly.io/),iPhone 用数据线连接
2. 把 `LoginWebApp-unsigned.ipa` 拖进 Sideloadly
3. 填入你的 Apple ID → Start
4. iPhone:**设置 → 通用 → VPN与设备管理** → 信任该开发者证书

> 免费 Apple ID 签名有效期 **7 天**,到期重签即可(无需重新构建)。
> 付费开发者账号为 1 年。

---

## 5. 改代码 → 重新出包

### 常见修改:换网址 / 换账号

只改 [`native/Sources/Config.swift`](native/Sources/Config.swift):

```swift
/// 登录成功后加载的网址
static let homeURL = URL(string: "https://www.bing.com")!

/// 可用账号:用户名 -> 密码
static let validUsers: [String: String] = [
  "admin": "123456",
  "test": "test"
]
```

`Info.plist` 已开启 `NSAllowsArbitraryLoads`,因此 `http://` 网址也能加载。

### 提交与推送(本机有两个坑,照抄即可)

```powershell
# 工作目录
Set-Location 'e:\测试ipa随便写一个\ios-login-app'

git add -A

# 坑 1:本机无 git 全局提交身份,必须用 -c 临时传入(不要去改全局 config)
git -c user.name="hua-zi372" -c user.email="hua-zi372@users.noreply.github.com" `
    commit -m "你的提交说明"

git push
```

**坑 2:git 凭据账号错配。** 本机缓存的凭据属于另一个账号(`jk936694120`),
直接 push 会报 403 `Permission denied`。已通过在 remote URL 里写死用户名解决:

```
origin = https://hua-zi372@github.com/hua-zi372/ios-login-app.git
```

**不要把它改回不带用户名的形式**,否则 403 会复发。

> PowerShell 提示:语句分隔用 `;`,**不能用 `&&`**。

---

## 6. 构建失败怎么排错(重点)

GitHub 的**日志正文需要登录才能读**,匿名访问返回 403。
但 **annotations API 匿名可读**(已实测),可直接拿到真实错误。

### 查构建状态 + 定位失败步骤 + 读真实错误

```powershell
python -c "
import urllib.request,json
def get(u):
    req=urllib.request.Request(u,headers={'User-Agent':'diag','Accept':'application/vnd.github+json'})
    return json.load(urllib.request.urlopen(req,timeout=30))
base='https://api.github.com/repos/hua-zi372/ios-login-app'

run=get(base+'/actions/runs')['workflow_runs'][0]
print('run#',run['run_number'],run['status'],run['conclusion'])

# 哪一步失败
job=get(base+'/actions/runs/%d/jobs'%run['id'])['jobs'][0]
for s in job['steps']: print('  step',s['number'],s['name'],'->',s['conclusion'])

# 真实错误(annotations,匿名可读)
for c in get(base+'/commits/'+run['head_sha']+'/check-runs')['check_runs']:
    for x in get(base+'/check-runs/%d/annotations'%c['id']):
        print('  ANN|',(x.get('message') or '')[:300])

# 成功时看产物
if run['conclusion']=='success':
    for a in get(base+'/actions/runs/%d/artifacts'%run['id'])['artifacts']:
        print('  ARTIFACT:',a['name'],a['size_in_bytes'],'bytes')
"
```

### 第二条通道:Job Summary

工作流第 6 步在失败时会把 `error:`、`BUILD FAILED`、`Undefined symbol`、
`linker command failed` 等关键行提取到 **Actions run 页面顶部的 Summary 区块**,
标题为 `## Build errors (key lines)`。

### 排错铁律(血泪教训)

> **拿到真实错误再动手改。** 本项目曾因拿不到日志而盲猜修了 3 轮,全部修错
> ——修的都是上游早已内置的补丁,完全没触及真因。

另外:日志里的 `Supported platforms for the buildables in the current scheme is empty`
是**噪音**,不是失败原因,不要追它。

---

## 7. 为什么弃用 Expo(别再走回头路)

项目最初是 Expo SDK 58 + React Native,**连续 5 次云端构建失败**。

**真实原因**:Expo 自带的 `expo-modules-jsi` 在云端 Xcode 26.3(Swift 6.2)下编译报

```
JavaScriptObject.swift:946: error: sending 'slot' risks causing data races
```

即 Swift 6 严格并发检查与该库不兼容——**是上游库自身的 bug,不是本项目代码问题。**

已验证无效的修法,不要重试:

| 尝试 | 结果 |
|---|---|
| 移除嵌套 xcodebuild 的 `-quiet`(expo#50482) | 无效,该版本已内置 |
| 固定 `SYMROOT`/`OBJROOT`(expo#46326 / PR#46377) | 无效,该版本已内置 |
| 把 podspec 的 `swift_version` 从 6.0 降到 5.0 | **错误做法**,该库源码大量使用 `sending`、`consuming sending` 等 Swift 6 专属语法,降级直接语法报错 |

**换纯原生后的收益**(实测对比):

| | Expo 方案 | 纯原生方案 |
|---|---|---|
| 依赖 | 600+ JS 模块、Hermes、70+ CocoaPods | **0** |
| CI 编译耗时 | ~5 分钟 | **~30 秒** |
| 构建结果 | 连续 5 次失败 | **一次通过** |

---

## 8. 已验证记录

| 项 | 结果 |
|---|---|
| 最近成功构建 | run #7 / 提交 `bd6b72d` |
| 首次成功构建 | run #6 / RUNID `40747287466` / 提交 `b69e74c` |
| 步骤 | 全部 success(错误摘要步骤被正确 skip) |
| 产物 | `ios-unsigned-ipa`,约 39.4 KB |
| 编译耗时 | 约 30 秒(含排队总计 1~2 分钟) |
| 架构 | arm64,Release,iphoneos |
| 最低系统 | iOS 15.0;iPhone + iPad 均支持 |

---

## 9. 遗留事项(可选清理)

根目录的 Expo 残留文件(`package.json`、`App.js`、`index.js`、`app.json`、
`src/`、`assets/`、`scripts/patch-expo-jsi.py`)仍在仓库中,**不影响构建**,
但会误导人与 AI 判断技术栈。确认不再需要回看 RN 代码后可删除
(git 历史中仍可追溯)。
