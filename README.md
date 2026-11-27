# RdpAdmin

面向「敲门式」RDP 主机的 Windows 服务器簿：把“敲门 + 连远程桌面”收进一个列表，点一下就走完。

这类主机的 RDP 端口平时是关着的，要先对敲门页发一次带令牌的请求（HTTP GET），
服务端才会对来源 IP 临时放行。RdpAdmin 就是替操作员记住这些事的那一层：

- 保存服务器清单：名称、地址、端口、登录账户、密码、敲门 URL、是否管理会话；
- 首次连接当天先敲一次门；敲门失败不会把“今天已敲过”记上，下一次会重敲；
- 密码用当前 Windows 用户的 DPAPI 加密后存在本地文件里，连接时通过 `CredWrite`
  交给系统凭据库，再由系统自带的 `mstsc` 读走——密码不进命令行，也不进日志；
- 不装服务、不写注册表、不联网上报任何数据。

它不依赖任何特定的服务端实现：只要敲门页是"GET 一个带令牌的 URL、服务端按来源 IP 放行"
这一种，就能用。RdpBan 的敲门 URL 是最常见的参考格式，但本工具不包含、也不修改
它的过滤器、守护进程或控制台。

Code signing policy: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)

## 构建

需要 .NET SDK（任意能编译 net452 的版本；项目已引用
`Microsoft.NETFramework.ReferenceAssemblies`，所以不必预装 4.5.2 targeting pack）。

```powershell
dotnet build RdpAdmin.csproj -c Release
```

产物在 `bin\Release\net452\RdpAdmin.exe`。单文件，无依赖，可直接拷走运行。

Windows Server 2008 R2 级别的操作机也能跑（.NET Framework 4.5 起）。

## 使用

1. 双击 `RdpAdmin.exe`；
2. 「添加」一台服务器：填地址或名称（只填一个，另一个会自动跟上）、端口、账户、密码，
   粘贴服务端给你的整条敲门 URL（RdpBan 控制台「敲门路径」窗口里给的就是这个格式）；
3. 选中一行按「连接」：需要时先敲门，然后把密码交给系统凭据库并启动 `mstsc`。

数据存在当前用户的 `%LOCALAPPDATA%\RdpAdmin\servers.dat`。密码字段是 DPAPI 密文，
换一个 Windows 账户复制这个文件解不开——这是有意的。

## 安全说明（请先读）

- 密码确实会以明文短暂存在于进程内存里（要交给 `CredWrite`，绕不开）；
  它不会被写到磁盘明文、不会出现在命令行参数、不会进任何日志。
- 敲门 URL 里通常带一次性/长期令牌，`servers.dat` 里存的是整条 URL；
  这个文件按当前用户加密保护的范围**只有密码字段**，URL 与地址是明文。
  别把 `servers.dat` 传到聊天工具或版本库。
- 程序会调用系统 `mstsc.exe`，不会自带或替换远程桌面客户端。
- 没有自动更新、没有遥测、没有后台常驻。

## 代码签名

发布包的签名策略见 [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)。
当前仓库里的本地构建默认未签名；正式 Release 在拿到证书后统一签名。

## 许可证

MIT，见 [LICENSE](LICENSE)。

## 背景

本仓库是独立发布的源码与构建：单个 WinForms 文件，没有外部依赖，构建脚本和 CI 都在仓库内。
作者同时维护 RdpBan（RDP 防护与敲门服务端），本工具与它的敲门 URL 格式兼容，
但代码、构建和发布完全独立；RdpBan 的过滤器、守护进程和控制台不在本仓库内。
