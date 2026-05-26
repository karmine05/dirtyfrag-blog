---
title: "SHADOW-EARTH-053: A Kill-Chain Walkthrough and Fleet Detection Pack"
date: 2026-05-26T11:00:00-04:00
draft: false
tags: ["fleet", "osquery", "windows", "linux", "macos", "exchange", "threat-intel", "detection-engineering", "shadowpad", "china-nexus"]
categories: ["security-ops"]
description: "A Lockheed kill-chain and per-stage Diamond Model for Trend Micro's newly named SHADOW-EARTH-053 intrusion set, paired with a Fleet/osquery detection bundle validated against the current Fleet table schema."
summary: "Trend Micro named SHADOW-EARTH-053 on 30 April 2026 — a China-aligned ProxyLogon + GODZILLA + ShadowPad campaign across South/East/Southeast Asia and one NATO target. This post walks the campaign through Lockheed's seven kill-chain stages with a Diamond Model rendered per stage, then ships a validated Fleet/osquery detection pack: 18 queries audited against fleetdm.com/tables, schema bugs corrected, platform pinning enforced. Three behavioural lenses (web-shell + IIS abuse, ShadowPad persistence + tunnels, credential theft + mailbox export) covering Windows, Linux, macOS."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

> **TL;DR:** Trend Micro published *Inside SHADOW-EARTH-053* on 30 April 2026. The intrusion set has been operational since at least December 2024, exploits ProxyLogon against unpatched Exchange/IIS, drops GODZILLA web shells, loads ShadowPad via DLL-sideloading with the payload stashed in a per-host registry key, and exfiltrates executive mailboxes over EWS. This post maps the campaign to Lockheed's kill chain with a Diamond Model rendered per stage, then ships a Fleet/osquery detection bundle — every query validated against the current Fleet table schema before publication.

| | |
|---|---|
| **Cluster** | SHADOW-EARTH-053 (Trend Micro temporary intrusion set; companion -054 in the same reporting) |
| **First observed** | December 2024 (per Trend Micro telemetry) |
| **Public report** | [Trend Micro, 30 Apr 2026 — Lunghi & Silva](https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html) |
| **Targets** | Government, defence, IT consultancies with MoD contracts, telecoms, transportation — Pakistan, Thailand, Malaysia, India, Myanmar, Sri Lanka, Taiwan, plus one NATO state (Poland) |
| **Initial access** | ProxyLogon (CVE-2021-26855/26857/26858/27065) on unpatched Exchange + IIS |
| **Implant** | ShadowPad (32-bit, older builder; per-host shellcode in `HKCU\Software\[ComputerName]\scode`) |
| **Linux side** | NOODLERAT ELF via CVE-2025-55182 React2Shell — Trend attributes to -053 with **low confidence** |
| **Behavioural lenses** | Web-shell on Exchange/IIS · ShadowPad persistence + layered tunnels · credential theft + mailbox export |

---

## Why a CISO should care about this one specifically

There are two reasons to read past the headline.

The first is that the **initial-access vector is a five-year-old patch gap**. SHADOW-EARTH-053 is not living off the bleeding edge — it lives off the long tail of Exchange servers that were never finished. Trend Micro frame this directly in the report: *"These older Microsoft Exchange vulnerabilities continue to serve as effective initial access vectors. SHADOW-EARTH-053's successful exploitation of these long-patched issues confirms that organizations still running legacy or unpatched Exchange servers remain at significant risk of mailbox compromise, credential theft, and prolonged attacker access."* If your patch programme has an exception for the Exchange box that nobody touches because it predates the current sysadmin, that is your detection surface.

The second is **what's lingering**. Tom Kellermann (VP at TrendAI, quoted by *The Register* on the same day) framed it as: *"I'm concerned about what they are leaving behind: What type of C2 on a sleep cycle is still lingering in these environments? Whether or not they have already prepositioned wipers or destructive capabilities."* Kellermann positions -053 and -054 as the *"younger brother and sister of the Typhoon campaigns"* — island-hopping through defence ministries of US-aligned nations and pro-Taiwan governments. That is the editorial framing, not Trend Micro's attribution; the report itself states that **no strong overlap with any publicly reported group** has been established for -053.

For comparison reading, CISA's joint advisory on Salt Typhoon ([AA25-239A, August 2025](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)) gives you the policy-level framing for the Typhoon family; -053 is the operationally-similar but distinct cousin.

---

## Diamond Model — campaign view

Before we walk the kill chain stage by stage, here is the Diamond Model rendered for the campaign as a whole. The per-stage versions later in the post specialise it.

<table>
<thead><tr><th colspan="2">SHADOW-EARTH-053 — Campaign Diamond</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>China-aligned cyberespionage operator. Provisional cluster — no public attribution to a named group. ShadowPad use places it in the shared post-2019 China-aligned ecosystem (originally APT41-only, since shared). TrendAI assesses operations align with PRC strategic interests in South/East/Southeast Asia and Taiwan.</td></tr>
<tr><th>Capability</th><td>ProxyLogon exploitation; GODZILLA web shells; ShadowPad (older builder, no anti-debug); DLL-sideloading via four signed-binary pairs + Toshiba Bluetooth Stack; registry-stored shellcode (<code>scode</code>); IOX + GOST + Wstunnel + a renamed <code>tunnel-core</code>; AnyDesk LotL; Mimikatz via rundll32; Evil-CreateDump; <code>newdcsync</code>; Sharp-SMBExec; <code>ExchangeExport</code> over EWS; RingQ packer.</td></tr>
<tr><th>Infrastructure</th><td>C2 IPs <code>141.164.46.77</code> (mdync beacon), <code>96.9.125.227</code> (GOST/Wstunnel, port 8067), <code>194.38.11.3:1790</code> (ShadowPad + NOODLERAT staging). Domain <code>check.office365-update.com</code> (NOODLERAT, registered 2025-11-19). Public staging directories on victims (<code>C:\Users\Public</code>, <code>C:\ProgramData</code>).</td></tr>
<tr><th>Victim</th><td>Government and critical-infrastructure entities in Pakistan, Thailand, Malaysia, India, Myanmar, Sri Lanka, Taiwan + one NATO state (Poland, defence sector). IT consultancies whose customer lists include the Ministry of Defence in their country. Transportation sector in Southeast Asia. Active since December 2024.</td></tr>
</tbody></table>

---

## Lockheed kill chain — stage by stage

Each stage below has the observed TTPs from the Trend report, a Diamond rendered for *that stage only*, and the ATT&CK techniques that map to it. The ATT&CK IDs are derived — the Trend report does not enumerate them — so cross-check against your own framework before pasting into a SIEM correlation rule.

### Stage 1 — Reconnaissance

External reconnaissance for unpatched Exchange/IIS surface. Trend does not publish the scanning infrastructure, but the consistent selection of ProxyLogon-vulnerable hosts implies systematic enumeration of public-facing Exchange servers in the target geographies. AnyDesk being used as a *first*-stage delivery channel in one intrusion suggests credentials obtained from a prior breach or commodity stealer logs may seed some target lists.

<table>
<thead><tr><th colspan="2">Diamond — Reconnaissance</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>SHADOW-EARTH-053 operator (provisional China-aligned cluster).</td></tr>
<tr><th>Capability</th><td>Public-facing service enumeration (implied). Possible reuse of prior-breach credentials for AnyDesk seeding.</td></tr>
<tr><th>Infrastructure</th><td>External scanning infrastructure (unattributed). For one delivery path: a pre-existing foothold or stealer-log marketplace credential.</td></tr>
<tr><th>Victim</th><td>Internet-facing OWA / IIS endpoints exposing legacy Exchange 2013/2016/2019 builds in SE Asia + Poland.</td></tr>
</tbody></table>

**ATT&CK:** T1595.002 (Active Scanning — Vulnerability Scanning), T1592 (Gather Victim Host Information).

### Stage 2 — Weaponisation

The weaponisation is in the loader trio, not in the exploit. ShadowPad arrives as three artefacts:

1. A legitimate, *signed* executable vulnerable to DLL sideloading.
2. A malicious DLL co-located with that executable.
3. The encrypted ShadowPad payload, stored in the registry and deleted after first use.

Trend lists four sideload pairs by SHA-256:

| Original | Renamed to | Malicious DLL | Authenticode signer |
|---|---|---|---|
| GameHook.exe | runtimebroker.exe / nvcontainer.exe | graphics-hook-filter32.dll | ORANGE VIEW LIMITED |
| imecmnt.exe | RuntimeBroker.exe / osppsvc.exe | imjp14k.dll | Microsoft Corporation |
| xReport.exe | — | Uxtheme.dll | Mainline Net Holdings Limited |
| LUManager.EXE | RAVCpl64.exe | MPS.dll | Samsung Electronics CO., LTD. |

Plus the Toshiba Bluetooth Stack binary renamed `CIATosBtKbd.exe`, sideloading `TosBtKbd.dll`, which reads the encrypted payload from `HKCU\Software\[ComputerName]\scode` and executes it via `EnumDesktopsA` callback injection.

<table>
<thead><tr><th colspan="2">Diamond — Weaponisation</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Operator with access to an *older* ShadowPad builder (no anti-debug / anti-VM features). Trend reads this as builder-only access, not source.</td></tr>
<tr><th>Capability</th><td>Five DLL-sideload pairs, 32-bit ShadowPad, registry-storage shellcode loader (<code>TosBtKbd.dll</code> → <code>EnumDesktopsA</code> callback).</td></tr>
<tr><th>Infrastructure</th><td>Not externally observable at this stage — pre-deployment artefacts.</td></tr>
<tr><th>Victim</th><td>N/A (pre-delivery).</td></tr>
</tbody></table>

**ATT&CK:** T1027 (Obfuscated Files or Information), T1574.002 (DLL Side-Loading) — though side-loading is observed at Installation, the kit-build for it happens here.

### Stage 3 — Delivery

Two delivery paths.

**Primary path:** direct exploitation of Microsoft Exchange via the ProxyLogon chain — CVE-2021-26855 (SSRF), CVE-2021-26857 (insecure deserialisation), CVE-2021-26858 (arbitrary file write), CVE-2021-27065 (post-auth arbitrary file write). The same chain Hafnium used in early 2021; five years later, the long tail of unpatched servers is still wide enough that Trend observed the cluster relying on it as primary.

**Secondary path:** AnyDesk as the delivery channel in at least one intrusion. Trend cannot say whether this represents an alternative initial access vector or a later-stage handoff from an earlier compromise, but the operational pattern is the same — leverage a signed, EDR-tolerated RAT to walk ShadowPad onto the target.

**Tertiary, low-confidence:** Linux NOODLERAT delivery via CVE-2025-55182 React2Shell exploitation, with implant retrieval from `194.38.11.3:1790`.

<table>
<thead><tr><th colspan="2">Diamond — Delivery</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Same operator. Multi-channel (Exchange, AnyDesk, Linux web app).</td></tr>
<tr><th>Capability</th><td>ProxyLogon RCE chain. AnyDesk handoff. React2Shell (CVE-2025-55182) — low-confidence link.</td></tr>
<tr><th>Infrastructure</th><td><code>194.38.11.3:1790</code> as ShadowPad + NOODLERAT staging host. AnyDesk relay infrastructure (legitimate provider).</td></tr>
<tr><th>Victim</th><td>Internet-facing Microsoft Exchange (legacy builds). Hosts with AnyDesk allowed. Linux web servers running vulnerable React2Shell builds.</td></tr>
</tbody></table>

**ATT&CK:** T1190 (Exploit Public-Facing Application), T1219 (Remote Access Software — AnyDesk).

### Stage 4 — Exploitation

ProxyLogon SSRF + post-auth file-write gives RCE under the IIS worker `w3wp.exe`. Trend captured the operator running domain admin enumeration, `nltest /dclist`, `nslookup` against internal Exchange servers, `csvde.exe` for AD CSV export, and PowerView's `Get-DomainUser` cmdlet — all *under the web-shell process tree*. They also dropped a 28 KB custom binary `DomainMachines.exe` that enumerates machines over LDAP and probes ports 139/445 (SMB), 80/443/8080/8443 (HTTP), 3389 (RDP), 5985/5986 (WinRM), 3306 (MySQL), 1433 (MSSQL), 88 (Kerberos).

<table>
<thead><tr><th colspan="2">Diamond — Exploitation</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Hands-on-keyboard operator working through the web shell.</td></tr>
<tr><th>Capability</th><td>ProxyLogon RCE; living-off-the-land AD enumeration (csvde, nltest, nslookup, PowerView); custom <code>DomainMachines.exe</code> LDAP enumerator.</td></tr>
<tr><th>Infrastructure</th><td>Victim's own Exchange/IIS as exploitation platform. <code>w3wp.exe</code> as process parent for all post-exploit commands.</td></tr>
<tr><th>Victim</th><td>Active Directory, internal Exchange servers, domain controllers visible from the Exchange DMZ.</td></tr>
</tbody></table>

**ATT&CK:** T1190 (initial), T1059 (Command and Scripting Interpreter), T1018 (Remote System Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery).

### Stage 5 — Installation

Three persistence anchors layered:

1. **GODZILLA web shells** dropped under Exchange/IIS web roots (`C:\inetpub\wwwroot\aspnet_client\system_web\` and `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\`). Twelve filenames observed — `error.aspx`, `errorFE.aspx`, `signout.aspx`, `warn.aspx`, `data.aspx`, `page.aspx`, `TimeinLogout.aspx`, `timeout.aspx`, `charcode.aspx`, `tunnel.ashx`, `i.aspx`, `2.aspx`. The `.ashx` HTTP handler variant is new for this cluster.
2. **ShadowPad loader** sideloaded into a legitimate signed binary in `C:\Users\Public` or `C:\ProgramData`, with the encrypted shellcode in `HKCU\Software\[ComputerName]\scode`.
3. **Scheduled Task `M1onltor`** running the sideloaded loader every five minutes with highest privileges.

<table>
<thead><tr><th colspan="2">Diamond — Installation</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Same operator. Sequential installation steps within a single session.</td></tr>
<tr><th>Capability</th><td>GODZILLA web shells, ShadowPad DLL-sideload loader, registry-stored shellcode, Scheduled Task <code>M1onltor</code> (5-min, highest priv).</td></tr>
<tr><th>Infrastructure</th><td>Victim's own filesystem (<code>C:\Users\Public</code>, <code>C:\ProgramData</code>), registry hive (<code>HKCU\Software\[ComputerName]\scode</code>), Task Scheduler.</td></tr>
<tr><th>Victim</th><td>Exchange + IIS web roots, every host receiving ShadowPad (often spread laterally; see Stage 6).</td></tr>
</tbody></table>

**ATT&CK:** T1505.003 (Server Software Component — Web Shell), T1574.002 (DLL Side-Loading), T1112 (Modify Registry — payload storage), T1053.005 (Scheduled Task/Job).

### Stage 6 — Command and Control

Layered redundant tunnels are the load-bearing C2 design:

- **IOX proxy.** Local accounts created with `LocalAccountTokenFilterPolicy=1` to enable Pass-the-Hash from any local admin (not only the built-in RID 500). Trend notes the registry-set in the IOX context specifically — the value itself is a generic UAC remote-token-filter bypass that's commonly set by lateral-movement toolkits, not exclusive to IOX.
- **GOST** as SOCKS5 + WebSocket tunnels to `96.9.125.227`.
- **Wstunnel** deployed as `wt.exe`, tunnelling SOCKS5 over HTTPS to the same `96.9.125.227`.
- A **renamed `tunnel-core.exe` → `code.exe`** invoked with parameter `client.toml`, talking to `96.9.125.227:8067`. The tool itself was not recovered.
- **AnyDesk** as a "conditionally allowed" RAT — signed, EDR-friendly, blends with legitimate IT operations.
- **`mdync.exe`** beaconing to `141.164.46.77`, dropped by `TosBtKbd.dll`. Binary not recovered.
- **NOODLERAT (Linux)** with C2 `check.office365-update.com` (registered 2025-11-19, low-confidence link).

<table>
<thead><tr><th colspan="2">Diamond — Command and Control</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Operator running multiple parallel channels for operational redundancy.</td></tr>
<tr><th>Capability</th><td>IOX, GOST, Wstunnel, custom <code>tunnel-core/code.exe</code>, AnyDesk, mdync beaconer, NOODLERAT (Linux).</td></tr>
<tr><th>Infrastructure</th><td><code>96.9.125.227</code> (GOST/Wstunnel/tunnel-core, port 8067), <code>141.164.46.77</code> (mdync beacon), <code>194.38.11.3:1790</code> (NOODLERAT staging), <code>check.office365-update.com</code> (NOODLERAT C2).</td></tr>
<tr><th>Victim</th><td>All compromised hosts in the victim network, with outbound 443/8067 + tunnel egress paths.</td></tr>
</tbody></table>

**ATT&CK:** T1071.001 (Application Layer Protocol — Web Protocols), T1090.001 (Internal Proxy), T1090.002 (External Proxy), T1219 (AnyDesk), T1071.004 (DNS — NOODLERAT C2).

### Stage 7 — Actions on Objectives

Three observed objective categories.

**Credential theft.** Mimikatz via `rundll32.exe` with `sekurlsa::logonpasswords` and `lsadump::sam`, spawned by `w3wp.exe`. Evil-CreateDump (a modified `create-dump.exe` retargeted at LSASS) for memory dumps. `newdcsync` for DCSync attacks against domain controllers.

**Lateral movement.** WMIC for installing backdoors on additional hosts. Sharp-SMBExec (a C# SMBExec). A custom RDP launcher binary named `smss.exe`. Web shells copied to additional internal Exchange servers over admin shares (`copy charcode.aspx \\<IP>\c$\inetpub\wwwroot\aspnet_client\system_web\`).

**Mailbox + IP exfiltration.** Iterative use of Exchange PowerShell: initial `Get-Mailbox` calls failed, the operator added `Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn`, refined to `Get-User`, layered in `userAccountControl` and `AccountDisabled` fields to identify active high-value accounts. A custom **`ExchangeExport`** tool then exported high-profile mailboxes via the EWS API — Trend notes this is the same operational pattern Microsoft observed from Silk Typhoon (Hafnium). At least one observed exfil run produced a password-protected RAR archive containing an executive's PST file.

Defence evasion overlays the entire stage: **RingQ** packer to evade signature-based detection, `net.exe` and PowerShell copied into `C:\ProgramData` with `$<RANDOM>.log` filenames to defeat process-name-based detection.

<table>
<thead><tr><th colspan="2">Diamond — Actions on Objectives</th></tr></thead>
<tbody>
<tr><th>Adversary</th><td>Operator pursuing long-term espionage objectives (mailbox theft, IP exfil) rather than smash-and-grab.</td></tr>
<tr><th>Capability</th><td>Mimikatz (rundll32), Evil-CreateDump, <code>newdcsync</code>, WMIC, Sharp-SMBExec, custom RDP <code>smss.exe</code>, <code>ExchangeExport</code> + EWS, password-protected RAR, RingQ packer, randomised binary renames.</td></tr>
<tr><th>Infrastructure</th><td>Compromised domain controllers (for DCSync), internal Exchange servers (for mailbox export), all C2 channels in Stage 6 for exfil egress.</td></tr>
<tr><th>Victim</th><td>Executive mailboxes, AD credentials, KRBTGT (via DCSync), IT consultancies as supply-chain pivots toward government MoD customers.</td></tr>
</tbody></table>

**ATT&CK:** T1003.001 (LSASS Memory), T1003.006 (DCSync), T1218.011 (Rundll32), T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1560.001 (Archive via Utility), T1114.002 (Remote Email Collection), T1036.005 (Match Legitimate Name).

---

## Detection lenses — three behavioural axes, every query validated

The TTPs above collapse into three behavioural lenses for detection:

1. **Web shell + Exchange/IIS abuse** (Stages 3, 4, 5 — initial access through `w3wp.exe` LOLBIN spawns).
2. **ShadowPad persistence + layered tunnels** (Stages 5, 6 — sideload loader, registry shellcode, Scheduled Task, IOX/GOST/Wstunnel/AnyDesk).
3. **Credential theft + mailbox export** (Stage 7 — LSASS, DCSync, EWS PST export).

Every osquery query below was audited against the [current Fleet table schema](https://fleetdm.com/tables/). Notable schema realities to internalise before pasting:

- **`file.sha256` does not exist.** Hashes come from the `hash` table joined on `path`.
- **`file.directory IN (...)` violates osquery's required-equality constraint** and is rejected at runtime. Use repeated `directory = '...'` clauses joined with `OR`.
- **`file_events` and `socket_events` are macOS + Linux only.** On Windows, use the NTFS publisher, `process_etw_events`, or `windows_events`. A copy-pasted `file_events` query against a Windows host returns zero rows silently, which reads as "no threat" if you don't know.
- **`process_etw_events` does not expose `parent_path` / `parent_name`** — only `ppid`. Don't write subqueries against `processes` to recover the parent; the race window is real, and you should pivot in your SIEM/Fleet results pipeline instead.

Each query below is shown inline, footnoted to its Fleet doc page, and bundled as a downloadable SQL artifact at the end of the post.

### Lens 1 — Web shell + Exchange/IIS abuse

#### 1.1 Retro-hunt for GODZILLA web shell filenames (Windows, `file` + `hash`)

```sql
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE (f.directory = 'C:\inetpub\wwwroot\aspnet_client\system_web'
    OR f.directory = 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth')
  AND f.filename IN ('error.aspx','errorFE.aspx','signout.aspx','warn.aspx','data.aspx',
                     'page.aspx','TimeinLogout.aspx','timeout.aspx','charcode.aspx',
                     'tunnel.ashx','i.aspx','2.aspx');
```

Schema notes: `file` requires equality on `directory` or `path` (see [fleetdm.com/tables/file](https://fleetdm.com/tables/file)), `sha256` lives on `hash` ([fleetdm.com/tables/hash](https://fleetdm.com/tables/hash)). Platform-pin: `windows`. Run as a one-shot live hunt across the Exchange/IIS label set; promote to a Fleet policy that *fails on any row* if you want continuous coverage.

#### 1.2 FIM for new ASPX/ASHX in Exchange/IIS roots (macOS/Linux only via osquery FIM; Windows uses NTFS publisher)

```sql
SELECT time, action, target_path, category
FROM file_events
WHERE category IN ('exchange_webroot','iis_webroot')
  AND (target_path LIKE '%.aspx' OR target_path LIKE '%.ashx');
```

Schema note: `file_events` is **macOS + Linux only** ([fleetdm.com/tables/file\_events](https://fleetdm.com/tables/file_events)). For Windows IIS FIM, set `enable_ntfs_event_publisher: true` in agent options and watch the NTFS event stream — there is no Windows equivalent of `file_events` in the standard osquery extension set. Define the `exchange_webroot` and `iis_webroot` categories under `file_paths:` in your agent config (snippet below).

#### 1.3 IIS worker spawning LOLBINs (Windows, ETW)

```sql
SELECT datetime, username, path, cmdline, ppid, pid, type
FROM process_etw_events
WHERE type = 'ProcessStart'
  AND (path LIKE '%\cmd.exe'
    OR path LIKE '%\powershell.exe'
    OR path LIKE '%\whoami.exe'
    OR path LIKE '%\net.exe'
    OR path LIKE '%\rar.exe'
    OR path LIKE '%\rundll32.exe');
```

Schema note: do *not* try to filter on `parent_name = 'w3wp.exe'` inside the query — `process_etw_events` doesn't expose parent metadata beyond `ppid` ([fleetdm.com/tables/process\_etw\_events](https://fleetdm.com/tables/process_etw_events)). Correlate to `w3wp` in your SIEM by joining on `(host_id, ppid)` against a companion `processes` query, or with the Sysmon EventID 1 stream via `windows_events`. Requires `enable_process_etw_events: true`. **High-FP without correlation** — `rundll32` and `cmd.exe` are noisy.

### Lens 2 — ShadowPad persistence + layered tunnels

#### 2.1 ShadowPad loader DLLs and binaries on disk (Windows, `file` + `hash`)

```sql
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE (f.path LIKE 'C:\Users\Public\%' OR f.path LIKE 'C:\ProgramData\%')
  AND (f.filename IN ('CIATosBtKbd.exe','TosBtKbd.dll','graphics-hook-filter32.dll',
                      'imjp14k.dll','Uxtheme.dll','MPS.dll')
       OR f.filename LIKE 'mdync.exe');
```

Six DLL/EXE names are the recoverable per-host artefacts from the four sideload pairs + the Toshiba loader. `mdync.exe` is the post-loader beaconer.

#### 2.2 ShadowPad shellcode in the registry (Windows)

```sql
SELECT path, key, name, type, mtime
FROM registry
WHERE path LIKE 'HKEY_USERS\%\Software\%\scode';
```

`HKEY_USERS\<SID>\Software\<ComputerName>\scode` is the osquery-visible form of `HKCU\Software\[ComputerName]\scode` across every loaded user hive. The `<ComputerName>` element will be specific to each victim host. Make this a Fleet policy that fails on any returned row — there is no legitimate reason for a value named `scode` to exist directly under `HKCU\Software\<hostname>`.

#### 2.3 Scheduled Task `M1onltor` (Windows)

```sql
SELECT name, action, enabled, state, last_run_time, next_run_time, path
FROM scheduled_tasks
WHERE name = 'M1onltor'
   OR path LIKE 'C:\Users\Public\%'
   OR path LIKE 'C:\ProgramData\%';
```

The literal task name `M1onltor` is a specific IOC; the `path LIKE` clauses generalise to "any scheduled task whose executable lives in a publicly-writable directory" — the operational pattern Trend observed for staging.

#### 2.4 `LocalAccountTokenFilterPolicy` flipped to 1 (Windows)

```sql
SELECT path, name, data, mtime
FROM registry
WHERE path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  AND name = 'LocalAccountTokenFilterPolicy'
  AND data = '1';
```

Trend Micro ties this registry-set to the operator's IOX deployment specifically, but the value itself is the **generic Microsoft UAC remote-restriction bypass** ([KB951016](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)) — it disables remote token filtering for local administrator accounts other than the built-in RID 500. Plenty of legitimate tooling sets it. Treat a `1` value as "explain why this is here" rather than auto-incident.

#### 2.5 Tunnel binaries by name and command line (Windows)

```sql
SELECT pid, name, path, cmdline, parent
FROM processes
WHERE name IN ('iox.exe','gost.exe')
   OR cmdline LIKE '%--listen socks%'
   OR cmdline LIKE '%client.toml%'
   OR cmdline LIKE '%wstunnel%';
```

`code.exe` and `wt.exe` are intentionally omitted from the `name` predicate — they collide with Visual Studio Code and Windows Terminal respectively, and would generate noise on every developer workstation. The `cmdline LIKE '%client.toml%'` branch catches the renamed `tunnel-core`/`code.exe` invocation that Trend observed.

#### 2.6 AnyDesk inventory and unexpected outbound (macOS/Linux variant; Windows uses Sysmon)

```sql
-- Inventory: where AnyDesk is installed
SELECT name, version, install_location, publisher
FROM programs
WHERE name LIKE '%AnyDesk%';

-- Network activity (macOS + Linux only — socket_events is not available on Windows)
SELECT s.time, s.action, s.remote_address, s.remote_port,
       p.pid, p.name, p.path, p.cmdline
FROM socket_events s
JOIN processes p USING (pid)
WHERE p.name LIKE 'AnyDesk%'
  AND s.action = 'connect'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT REGEXP '^172\.(1[6-9]|2[0-9]|3[01])\.'
  AND s.remote_address NOT LIKE '127.%';
```

The original RFC1918 exclusion in many published recipes only matches `172.16.%`, missing the rest of `172.16.0.0/12`. The `REGEXP` form above covers the full range. Scope by Fleet label — "Tier 0", "Exchange servers", "Domain Controllers" — so that helpdesk laptops legitimately using AnyDesk don't drown the signal. On Windows, equivalent telemetry comes from Sysmon EventID 3 via `windows_events`.

#### 2.7 Connections to Trend-published C2 infrastructure (Linux/macOS; Windows uses Sysmon)

```sql
SELECT s.time, s.action, s.remote_address, s.remote_port, p.pid, p.name, p.path
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.action = 'connect'
  AND (s.remote_address IN ('141.164.46.77','96.9.125.227','194.38.11.3')
       OR s.remote_port IN (8067, 1790));
```

These three IPs are the campaign IOCs Trend Micro published on 30 April 2026. Treat them as **rotating atomic indicators** — they will burn within weeks of publication. The port-based fallback (`8067`, `1790`) is slightly more stable but still narrow. The behavioural shape — non-browser process initiating long-lived 443/8443 connections from a server-class host — is the durable signal; build the SIEM rule that way and use the atomic IOCs as enrichment.

### Lens 3 — Credential theft + mailbox export

#### 3.1 `rundll32` with Mimikatz signatures (Windows, via Sysmon → `windows_events`)

```sql
SELECT datetime, data
FROM windows_events
WHERE source = 'Microsoft-Windows-Sysmon'
  AND eventid = 1
  AND data LIKE '%rundll32.exe%'
  AND (data LIKE '%sekurlsa::logonpasswords%'
    OR data LIKE '%lsadump::sam%'
    OR data LIKE '%lsadump::dcsync%'
    OR data LIKE '%newdcsync%');
```

Requires Sysmon installed on the endpoint, `enable_windows_events_publisher: true` in Fleet agent options, and the Sysmon channel subscribed. Without Sysmon: zero rows. Document this dependency in your detection-engineering inventory — the Mimikatz-via-rundll32 pattern is the highest-confidence credential-theft signal in the report.

#### 3.2 Exchange PowerShell enumeration and `ExchangeExport` (Windows)

```sql
SELECT datetime, script_name, script_path, script_text, cosine_similarity
FROM powershell_events
WHERE script_text LIKE '%Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn%'
   OR script_text LIKE '%Get-Mailbox%'
   OR script_text LIKE '%Get-User%'
   OR script_text LIKE '%New-MailboxExportRequest%'
   OR script_text LIKE '%ExchangeExport%'
   OR script_text LIKE '%userAccountControl%';
```

Requires Windows Script Block Logging enabled via GPO (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`) and `enable_powershell_events_subscriber: true` in agent options. The `cosine_similarity` column ([fleetdm.com/tables/powershell\_events](https://fleetdm.com/tables/powershell_events)) is a character-frequency anomaly score against osquery's built-in baseline — lower means more anomalous; add a row threshold like `cosine_similarity < 0.25` for an unsupervised fallback that catches scripts not in the IOC list above.

#### 3.3 PST creation on Exchange and file servers (macOS/Linux variant; Windows uses `file` snapshot)

```sql
-- macOS + Linux only — file_events not available on Windows
SELECT time, action, target_path, category
FROM file_events
WHERE action IN ('UPDATE','CREATED')
  AND target_path LIKE '%.pst';

-- Windows snapshot equivalent — pin to expected PST roots in your environment
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE f.directory = 'C:\Windows\Temp'
  AND f.filename LIKE '%.pst';
```

A 500 MB executive PST appearing in `C:\Windows\Temp` next to a `*.rar` of similar size is a high-confidence exfil-prep signal. Cross-correlate with Stage 7's `Get-Mailbox`/`Get-User` PowerShell traffic.

#### 3.4 macOS LaunchAgent persistence (in case operators pivot to Mac admin boxes)

```sql
SELECT label, path, program, program_arguments, run_at_load, keep_alive, username
FROM launchd
WHERE (run_at_load = '1' OR run_at_load = 'true')
  AND (keep_alive   = '1' OR keep_alive   = 'true')
  AND (program LIKE '/Users/%/Downloads/%'
    OR program LIKE '/Users/%/Library/%/tmp/%'
    OR program LIKE '/tmp/%'
    OR program LIKE '/private/tmp/%');
```

`launchd.run_at_load` and `launchd.keep_alive` are text columns whose values aren't uniformly normalised across plists ([fleetdm.com/tables/launchd](https://fleetdm.com/tables/launchd)) — the dual predicate covers `'1'` and `'true'`. Not in the Trend report, but included because an operator with executive-mailbox access often pivots to laptops with the Exchange admin's session intact, and a LaunchAgent in `/Users/<user>/Library/LaunchAgents` is the macOS analogue of the `M1onltor` Scheduled Task.

#### 3.5 Linux: unexpected outbound from web-tier hosts

```sql
SELECT s.time, s.remote_address, s.remote_port, p.pid, p.name, p.path, p.cmdline
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.action = 'connect'
  AND (
    (s.remote_address = '194.38.11.3' AND s.remote_port = 1790)
    OR s.remote_port IN (1790, 8080, 8443)
  )
  AND p.name NOT IN ('nginx','httpd','apache2','envoy','haproxy','traefik');
```

Web-tier hosts shouldn't be making outbound connections from anything other than the web server itself — the `NOT IN (...)` allowlist captures the legitimate exceptions. Pair with the NOODLERAT staging IP/port as a high-fidelity atomic indicator.

---

## Required Fleet agent options

Several queries above depend on evented tables and Windows publishers. Drop this into your Fleet agent options (or merge into an existing config) before running them:

```yaml
command_line_flags:
  disable_events: false

  # macOS + Linux: file integrity + process/socket via audit framework
  enable_file_events: true
  disable_audit: false
  audit_allow_process_events: true
  audit_allow_socket_events: true

  # Windows: NTFS, ETW, PowerShell, Windows Event Log
  enable_ntfs_event_publisher: true
  enable_process_etw_events: true
  enable_powershell_events_subscriber: true
  enable_windows_events_publisher: true

  # Retention sized for a busy Exchange / DC host
  events_max: 50000
  events_expiry: 86400
  events_optimize: true

config:
  file_paths:
    exchange_webroot:
      - 'C:\inetpub\wwwroot\**'
      - 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\**'
    iis_webroot:
      - 'C:\inetpub\wwwroot\**'
    windows_temp:
      - 'C:\Windows\Temp\**'
      - 'C:\Users\*\AppData\Local\Temp\**'
```

Two soft prerequisites that live outside Fleet:

- **Sysmon** installed on every Windows host you care about, with a Mimikatz-aware config (the swiftonsecurity / olafhartong baselines both work).
- **PowerShell Script Block Logging** enabled via GPO (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`). Without this, `powershell_events.script_text` is empty.

---

## What to make a Fleet policy vs a scheduled query

The detections split cleanly into two operational modes.

**Fleet policies (fail-on-any-row, page on failure).** These are the "should not exist" detections — a single row is a real finding worth waking someone up for.

- `1.1` GODZILLA web shell filenames in Exchange/IIS roots (any row = web shell on the box).
- `2.2` `scode` registry value under `HKCU\Software\<hostname>\` (any row = ShadowPad shellcode storage).
- `2.3` Scheduled Task named exactly `M1onltor`.
- `2.5` `iox.exe` / `gost.exe` running, or any process with `--listen socks` / `client.toml` / `wstunnel` in cmdline.
- `2.6` AnyDesk installed on a host labelled "Exchange servers" or "Domain Controllers".

**Scheduled queries (results into SIEM, correlate downstream).** These are the high-volume behavioural queries that need correlation before alerting.

- `1.3` IIS worker spawning LOLBINs.
- `2.4` `LocalAccountTokenFilterPolicy = 1`.
- `2.7` Connections to published C2 infrastructure.
- `3.1` `rundll32` Mimikatz signatures.
- `3.2` Exchange PowerShell enumeration.
- `3.5` Linux web-tier unexpected outbound.

---

## Limits and caveats

A blog post is a poor place to hide caveats, so the load-bearing ones go here:

1. **The Trend Micro `141.164.46.77`, `96.9.125.227`, `194.38.11.3`, `check.office365-update.com` atomic IOCs will burn fast.** Use them, but build the behavioural detections (process tree, registry, scheduled task) as the durable layer. Static IOCs rotate; the placement and the loading mechanism don't.
2. **Trend's NOODLERAT attribution to SHADOW-EARTH-053 is explicitly *low confidence*.** If you see NOODLERAT on a Linux host, work it as a separate Linux NOODLERAT incident first; the -053 link is supporting evidence, not the leading edge.
3. **No public attribution to a known named group exists for -053.** Tom Kellermann's "younger sibling of the Typhoons" framing is editorial — Trend Micro itself says they found no strong overlap with any publicly reported cluster. If your CTI shop is asked to "confirm" -053 is Salt Typhoon, the honest answer is *not yet*.
4. **`file_events` and `socket_events` are macOS + Linux only.** A copy-pasted query against a Windows host returns zero rows silently. Don't read zero as "clean." Use `process_etw_events`, `windows_events`, and the `file` snapshot pattern on Windows.
5. **`process_etw_events` parent correlation cannot live inside a single osquery query.** Correlate downstream — in your SIEM, in Fleet's results pipeline, or against a companion `processes` snapshot keyed by `(host_id, ppid)`.
6. **`LocalAccountTokenFilterPolicy = 1` is not exclusive to -053 or to IOX.** It's a generic UAC bypass written by many lateral-movement toolkits. Treat it as a context-builder, not a standalone IOC.

---

## Downloads

The full validated query set, plus the agent-options snippet, as standalone artefacts:

| Artefact | Link |
|---|---|
| Windows query bundle | [`/code/se053-windows-queries.sql`](/dirtyfrag-blog/code/se053-windows-queries.sql) |
| Linux query bundle | [`/code/se053-linux-queries.sql`](/dirtyfrag-blog/code/se053-linux-queries.sql) |
| macOS query bundle | [`/code/se053-macos-queries.sql`](/dirtyfrag-blog/code/se053-macos-queries.sql) |
| Fleet agent options snippet | [`/code/se053-fleet-agent-options.yml`](/dirtyfrag-blog/code/se053-fleet-agent-options.yml) |

---

## Sources

| | |
|---|---|
| Primary report | [Trend Micro — *Inside Shadow-Earth-053: A China-Aligned Cyberespionage Campaign Against Government and Defense Sectors in Asia*](https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html), Daniel Lunghi + Lucas Silva, 30 Apr 2026 |
| Press coverage + Tom Kellermann interview | [*The Register* — *Chinese spy group caught lurking in Poland, Asia networks*](https://www.theregister.com/2026/04/30/chinese_spies_lurking_networks/), 30 Apr 2026 |
| Secondary summary | [Industrial Cyber — *SHADOW-EARTH-053 targets Asian government, defense, critical infrastructure via Exchange and IIS vulnerabilities*](https://industrialcyber.co/ransomware/shadow-earth-053-targets-asian-government-defense-critical-infrastructure-via-exchange-and-iis-vulnerabilities/) |
| Typhoon family context (companion read) | [CISA — Joint Cybersecurity Advisory AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a), August 2025 |
| ShadowPad background | [Trend Micro — Earlier ShadowPad reporting referenced in the -053 attribution diagram](https://www.trendmicro.com/en_us/research/25/c/the-espionage-toolkit-of-earth-alux.html) |
| Fleet table reference (used throughout) | [fleetdm.com/tables](https://fleetdm.com/tables/) — every query above footnoted to its specific table page |
| UAC remote-restriction reference | [Microsoft KB951016 — `LocalAccountTokenFilterPolicy`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction) |
