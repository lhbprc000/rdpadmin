# Code signing policy

Official Windows executables from this project are Authenticode-signed so that
anyone who downloads them can tell that the binary was produced by this project's
build and has not been modified by a third party.

- What is signed: `RdpAdmin.exe` attached to each release on GitHub Releases.
- Where it comes from: the source at the tag for that release, built by GitHub
  Actions on a clean `windows-latest` runner; the build definition is
  `.github/workflows/build.yml` in this repository.
- How it is signed: through a hosted signing service. The private key stays in a
  hardware security module (HSM); it is never exported, never written to a
  `.pfx`, and never appears in the repository or in build logs.
- Certificate: the open-source certificate issued by
  [SignPath Foundation](https://signpath.org/) (OV level). If that application is
  not approved, a Certum Open Source Code Signing certificate is used instead.
- How to verify:

```powershell
Get-AuthenticodeSignature .\RdpAdmin.exe | Format-List Status,SignerCertificate
# or
signtool verify /pa /v RdpAdmin.exe
```

- Unsigned builds from a developer machine are for local testing only and are
  not distributed as releases.

Maintainer roles:

- Committer: merges changes and prepares the release.
- Signing approver: reviews the release build and approves signing.

The current maintainer is listed in [AUTHORS.md](AUTHORS.md) and in the
repository's commit history.
