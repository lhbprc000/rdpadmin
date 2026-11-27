# RdpAdmin

A Windows server book for operators of knock-gated RDP hosts: it keeps the server
list, performs the knock, and opens the desktop — one click, no typing the same
address, account and URL every day.

Hosts of this kind keep the RDP port closed until a request carrying a token
hits the knock page (an HTTP GET); only then does the server temporarily admit
the caller's source address. RdpAdmin remembers that part of the job:

- stores the server list: name, address, port, logon account, password, knock
  URL, and whether to open a console/management session;
- knocks once per day before the first connection; a failed knock is not
  recorded as done, so the next attempt knocks again;
- seals the password with the current Windows user's DPAPI key on disk, then
  hands it to the Windows credential store via `CredWrite` so the built-in
  `mstsc` can read it — the password never appears on a command line or in a log;
- installs no service, writes no registry values, and reports nothing anywhere.

It does not depend on a particular server-side implementation. Any knock page
that grants access for the caller's source address by way of a tokenized URL
works; the URL format produced by RdpBan is the reference implementation, but
this tool contains and modifies none of its filter, daemon, or console code.

Code signing policy: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)

## Build

Requires a .NET SDK able to build `net452` (the project references
`Microsoft.NETFramework.ReferenceAssemblies`, so the 4.5.2 targeting pack does
not have to be installed separately).

```powershell
dotnet build RdpAdmin.csproj -c Release
```

The result is a single executable at `bin\Release\net452\RdpAdmin.exe` with no
external dependencies — copy it and run.

It also runs on operator machines at the Windows Server 2008 R2 level
(.NET Framework 4.5 or newer).

## Usage

1. Start `RdpAdmin.exe`.
2. Choose **Add** and fill in a server: address or name (fill either one and the
   other follows), port, account, password, and paste the whole knock URL
   provided by the server (the RdpBan console's "knock path" window shows exactly
   this format).
3. Select a row and choose **Connect**: it knocks first when needed, writes the
   password to the credential store, and starts `mstsc`.

Data lives in `%LOCALAPPDATA%\RdpAdmin\servers.dat` for the current user. The
password field is a DPAPI blob; copying the file to another Windows account
yields nothing usable — that is intentional.

## Security notes (read first)

- The password is briefly present in plaintext in process memory; it has to be,
  to reach `CredWrite`. It is never written to disk in plaintext, never placed on
  a command line, and never logged.
- A knock URL usually carries a token, and `servers.dat` stores the whole URL.
  Only the password field is protected by the per-user encryption — addresses and
  URLs are plaintext. Do not send `servers.dat` through chat tools or commit it.
- The program launches the system `mstsc.exe`; it neither ships nor replaces the
  Remote Desktop client.
- No auto-update, no telemetry, no background process.

## Code signing

Release signing policy: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).
Local builds from this repository are unsigned by default; official releases are
signed once a certificate is available.

## License

MIT — see [LICENSE](LICENSE).

## Background

This repository is the standalone source and build: a single WinForms file, no
external dependencies, with the build script and CI kept in-tree. The author also
maintains RdpBan (an RDP protection and knock server), and this tool is compatible
with its knock URL format, but the code, build and release here are independent;
RdpBan's filter, daemon and console are not part of this repository.
