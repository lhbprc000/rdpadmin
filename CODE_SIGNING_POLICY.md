# Code signing policy

本项目对正式发布的 Windows 可执行文件做 Authenticode 签名，目标是让下载者能确认
“这个 exe 确实来自本项目的构建，而不是被第三方改过的副本”。

- 签名对象：GitHub Releases 页面上的 `RdpAdmin.exe`（每个正式版本）。
- 构建来源：同一 tag 对应的源码，由 GitHub Actions 在干净的 `windows-latest`
  环境中编译，构建脚本见 `.github/workflows/build.yml`。
- 签名方式：通过托管的签名服务完成，私钥保存在硬件安全模块（HSM）中，
  不导出、不落地成 `.pfx`；仓库和构建日志里不出现任何签名私钥或口令。
- 签名证书：由 [SignPath Foundation](https://signpath.org/) 提供的开源项目证书
  （OV 级）。若申请未通过，则使用由 Certum 签发的 Open Source Code Signing 证书。
- 校验方法：

```powershell
Get-AuthenticodeSignature .\RdpAdmin.exe | Format-List Status,SignerCertificate
# 或
signtool verify /pa /v RdpAdmin.exe
```

- 未签名的本地构建仅用于开发测试，不作为发布物分发。

维护者角色：

- 提交者（committer）：合入代码、发起 Release；
- 签名审批者（signing approver）：审核 Release 构建产物并批准签名。

当前维护者名单见仓库提交历史与 `AUTHORS.md`。
