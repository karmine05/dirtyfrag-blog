---
title: "SHADOW-EARTH-053: A Saturday-Morning Walkthrough and Fleet Detection Pack"
date: 2026-05-26T11:00:00-04:00
draft: false
tags: ["fleet", "osquery", "windows", "linux", "macos", "exchange", "threat-intel", "detection-engineering", "shadowpad", "china-nexus"]
categories: ["security-ops"]
description: "A first-person walkthrough of Trend Micro's SHADOW-EARTH-053 disclosure — Lockheed kill chain, per-stage Diamond Model, and a Fleet/osquery detection bundle validated against the current Fleet table schema."
summary: "Trend Micro dropped SHADOW-EARTH-053 on 30 April 2026 — China-aligned, ProxyLogon + GODZILLA + ShadowPad across South/East/Southeast Asia plus one NATO target. This is the walkthrough I ran when the report landed: kill chain mapped to Lockheed's seven stages with a Diamond Model per stage, a seven-day plan for what I'd do if it hit my SOC tomorrow, and an osquery detection pack with every query audited against fleetdm.com/tables before publication. Mermaid diamonds, a victimology map, a sideload-pairs visual, and a C2-tunnel architecture diagram included."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

It was a Saturday morning when the Trend Micro report dropped. I was working through the usual weekend ritual — coffee, RSS feeds, the SOC dashboards in another tab — and *Inside Shadow-Earth-053* slid past in my reader. Eight countries in Asia, one NATO target in Poland, ProxyLogon as the front door. My first reaction was honest: *ProxyLogon, again?* That chain is 2021. Five years ago. We should be past it.

But ProxyLogon is not the interesting thing in this report. The thing that stuck with me was the **registry-stored shellcode** — a Toshiba-signed binary renamed `CIATosBtKbd.exe`, sideloading a malicious `TosBtKbd.dll`, which calls `GetComputerNameA` to find a host-specific registry key (`HKCU\Software\<ComputerName>\scode`) and then executes the encrypted shellcode via `EnumDesktopsA` callback injection. That last bit is operator personality. You don't write code that abuses `EnumDesktopsA` as a callback target unless you've spent serious time studying which Windows APIs slip past behavioural EDR. The ProxyLogon is the door; this is the room.

What follows is the walkthrough I ran for myself on that Saturday. It's a kill chain mapped to Lockheed's seven stages with a Diamond Model rendered per stage, a notional seven-day SOC plan for what I'd do if this landed on my desk Monday morning, and an osquery detection pack — 18 queries, every one of them audited against the current Fleet table schema before I let it leave the page. I had to fix a handful of bugs in the generic version of these queries that's been circulating; those fixes are called out inline.

## The investigator's TL;DR

| | |
|---|---|
| **Cluster** | SHADOW-EARTH-053 (Trend Micro temporary intrusion set; companion -054 covered in the same reporting) |
| **First observed** | December 2024 (per Trend telemetry) |
| **Public report** | [Trend Micro — Lunghi & Silva, 30 Apr 2026](https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html) |
| **Targets** | Government, defence, IT consultancies with MoD contracts, telecoms, transportation — Pakistan, Thailand, Malaysia, India, Myanmar, Sri Lanka, Taiwan, plus Poland (NATO) |
| **Initial access** | ProxyLogon (CVE-2021-26855/26857/26858/27065) on unpatched Exchange + IIS |
| **Implant** | ShadowPad (32-bit, older builder; shellcode in `HKCU\Software\<ComputerName>\scode`) |
| **Linux side** | NOODLERAT ELF via CVE-2025-55182 React2Shell — Trend attributes to -053 with **low confidence** |
| **Why I care** | Long-tail patch gap as the entry, durable behavioural artefacts (registry + scheduled task + tunnel layering) as the persistence |

## Who got hit, and why those eight

Before any of the detection work, sit with the geography for a minute. Trend's victim list is not random.

{{< figure src="images/victimology-map.svg" alt="Victimology map: eight country footprint highlighting Pakistan, Thailand, Malaysia, India, Myanmar, Sri Lanka, Taiwan in Asia plus Poland as the single NATO target" caption="Eight countries, seven sectors. Asia-centred, with Poland's defence sector as the geographic outlier." >}}

What I read into the list is straightforward operator preference: governments aligned with the United States posture, governments supportive of Taiwan's independence, and the IT consultancies that hold contracts to those governments. The IT-consultancy angle is the supply-chain pivot — Trend noted one instance where -054 reached for the webmail of a Southeast Asian Ministry of Defence from inside a technology customer's environment. That is how this kind of campaign reaches the ministries that maintain better hygiene at the perimeter.

Poland is the outlier and worth the small footnote. Read it as opportunistic broadening rather than focused intent: the operator scans for ProxyLogon-vulnerable Exchange across the surface they can see, and Poland's defence sector had a server on that list. Trend Micro doesn't claim it as a strategic pivot, and I would not either.

## Why a CISO should read past the headline

Two reasons.

The first is that **the initial-access vector is a five-year-old patch gap**. SHADOW-EARTH-053 is not living off the bleeding edge — it lives off the long tail of Exchange servers that were never finished. Trend frames this directly: *"These older Microsoft Exchange vulnerabilities continue to serve as effective initial access vectors. SHADOW-EARTH-053's successful exploitation of these long-patched issues confirms that organizations still running legacy or unpatched Exchange servers remain at significant risk of mailbox compromise, credential theft, and prolonged attacker access."* If your patch programme has an exception for the Exchange box that nobody touches because it predates the current sysadmin, that exception is the surface.

The second is **what's lingering**. Tom Kellermann (VP at TrendAI, in *The Register* the same day) framed the lurking threat: *"I'm concerned about what they are leaving behind: What type of C2 on a sleep cycle is still lingering in these environments? Whether or not they have already prepositioned wipers or destructive capabilities."* He positioned -053 and -054 as the *"younger brother and sister of the Typhoon campaigns"* — island-hopping through defence ministries of US-aligned nations.

That last bit is editorial framing, not Trend Micro's attribution. The report itself states **no strong overlap with any publicly reported group exists** for -053. If your CTI shop is asked to confirm -053 is Salt Typhoon, the honest answer is *not yet*. For the policy-level companion read, CISA's joint advisory on Salt Typhoon ([AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a), August 2025) is the right cross-reference — same family of behaviour, distinct cluster.

## The campaign in one Diamond

Before the per-stage detail, here's the Diamond Model rendered for the campaign as a whole. The per-stage versions later specialise it.

{{< mermaid >}}
graph LR
  classDef adv  fill:#1a1a2e,stroke:#e94560,color:#fff,stroke-width:2px
  classDef cap  fill:#16213e,stroke:#0f3460,color:#fff,stroke-width:2px
  classDef inf  fill:#0f3460,stroke:#533483,color:#fff,stroke-width:2px
  classDef vic  fill:#533483,stroke:#e94560,color:#fff,stroke-width:2px
  A["<b>Adversary</b><br/>China-aligned operator<br/>ShadowPad ecosystem<br/>no public group overlap (-053)"]:::adv
  C["<b>Capability</b><br/>ProxyLogon + GODZILLA<br/>ShadowPad + 5 sideload pairs<br/>IOX / GOST / Wstunnel / NOODLERAT<br/>ExchangeExport via EWS"]:::cap
  I["<b>Infrastructure</b><br/>96.9.125.227 · 141.164.46.77<br/>194.38.11.3 · check.office365-update.com<br/>C:\\Users\\Public · C:\\ProgramData"]:::inf
  V["<b>Victim</b><br/>8 countries · 5 sectors<br/>1 NATO state (Poland)<br/>active since Dec 2024"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|targets| V
  V -.->|attracts| A
{{< /mermaid >}}

## The seven-day plan I'd run on Monday

If this report landed on my desk on Monday morning, here is the week I'd run. The queries it references are all in the [detection lenses](#detection-lenses-three-behavioural-axes-every-query-validated) section further down and in the [downloadable bundles](#downloads).

**Day 0 (today, end of Saturday).** Patch-posture review on every Exchange and IIS host. If ProxyLogon is still unpatched anywhere in the estate, that is the work — the rest of the queries only matter if the front door is closed. While the patch team is paged, I drop the three Trend C2 IPs (`141.164.46.77`, `96.9.125.227`, `194.38.11.3`) and the domain `check.office365-update.com` into the SIEM as block-and-alert. They will rotate within weeks of the Trend Micro publication, but in the next two weeks they are the highest-value atomic indicators.

**Day 1 (Monday).** Wire the validated query bundle into Fleet. Promote the *should-not-exist* queries — GODZILLA filenames in Exchange roots, the `scode` registry value, the scheduled task `M1onltor` — to Fleet **policies** so they fail-on-any-row. That gives me free continuous coverage with no SIEM-side correlation cost. The behavioural queries — `w3wp` LOLBIN spawns, Mimikatz-via-rundll32 signatures, Exchange PowerShell enumeration — go to scheduled queries feeding the SIEM.

**Day 2 (Tuesday).** SIEM correlation logic. The high-FP queries (`w3wp` spawning `cmd.exe` is not by itself an alert; `rundll32` is everywhere) need correlation rules built around them. The shape I want is: *if `w3wp.exe` spawned `cmd.exe`, AND the `scode` registry value appeared on the same host in the next four hours, page someone*. ETW doesn't expose parent names directly so the correlation has to happen here, not in the query.

**Day 3-4 (Wed-Thu).** The pivot work. AnyDesk inventory across every server-class label — Exchange, DCs, Tier 0. Anything that shouldn't have AnyDesk and does, raise a ticket. Pull `LocalAccountTokenFilterPolicy` state from every Windows host; the `1` value is not by itself an incident (Microsoft KB951016 documents it as the generic UAC remote-restriction bypass and plenty of legitimate tools set it), but it's the cheapest signal in the report.

**Day 5 (Friday).** Linux: hunt the React2Shell-vulnerable surface and look for the NOODLERAT C2 fingerprint. Trend's low-confidence attribution means I'm hunting for the *behaviour*, not betting on the link being -053.

**Day 7 (next Saturday).** Review what fired. Tune the noisy lenses (`rundll32`, tunnel-binary cmdline patterns) up or down based on false-positive volume. Promote any correlation rule that survived the week into the durable policy set. Document the week as a runbook in the SOC wiki — next time an operator from this ecosystem rotates infrastructure, the durable detection layer survives the IOC churn.

That plan is the wrapper. The kill chain that follows is the source material the plan is built from.

## Lockheed kill chain, one stage at a time

Each stage below has the TTPs from the Trend report, a Diamond rendered for *that stage*, the ATT&CK technique IDs that map to it, and — where useful — an inline visual. ATT&CK IDs are derived; Trend doesn't enumerate them. Cross-check against your own framework before pasting into a correlation rule.

{{< timeline >}}

{{< timelineItem icon="search" header="Stage 1 — Reconnaissance" badge="T1595" subheader="External enumeration of unpatched Exchange/IIS surface" md="true" >}}

External reconnaissance for unpatched Exchange/IIS surface. Trend doesn't publish the scanning infrastructure, but the consistent selection of ProxyLogon-vulnerable hosts implies systematic enumeration of public-facing Exchange in the target geographies. In one delivery path, AnyDesk shows up as the *first*-stage channel — that suggests credentials obtained from a prior breach or stealer-log marketplace may seed some target lists.

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>SHADOW-EARTH-053 operator<br/>(provisional China-aligned)"]:::adv
  C["<b>Capability</b><br/>Public-service scanning<br/>Possible stealer-log cred reuse"]:::cap
  I["<b>Infrastructure</b><br/>External scan hosts<br/>Cred marketplaces"]:::inf
  V["<b>Victim</b><br/>Internet-facing OWA<br/>Legacy Exchange 2013–2019"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|targets| V
{{< /mermaid >}}

**ATT&CK:** T1595.002 (Active Scanning — Vulnerability Scanning), T1592 (Gather Victim Host Information).

{{< /timelineItem >}}

{{< timelineItem icon="wand-magic-sparkles" header="Stage 2 — Weaponisation" badge="T1574.002" subheader="DLL sideload trio: signed binary + malicious DLL + registry shellcode" md="true" >}}

The weaponisation is in the loader trio, not in the exploit. ShadowPad arrives as three artefacts: a *legitimate, signed* executable vulnerable to DLL sideloading, a malicious DLL co-located with it, and the encrypted ShadowPad payload stored in the registry and deleted after first use. Four sideload pairs documented by SHA-256, plus a fifth Toshiba-signed loader that fetches the shellcode from `HKCU\Software\<ComputerName>\scode` and executes it via `EnumDesktopsA` callback injection.

{{< figure src="images/dll-sideload-pairs.svg" alt="Four DLL sideload pairs visualisation — GameHook.exe with graphics-hook-filter32.dll signed by ORANGE VIEW LIMITED; imecmnt.exe with imjp14k.dll signed by Microsoft Corporation; xReport.exe with Uxtheme.dll signed by Mainline Net Holdings; LUManager.EXE with MPS.dll signed by Samsung Electronics" caption="The trust isn't broken — it's borrowed. Each signed binary loads its co-located DLL exactly as Windows asks it to." >}}

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>Builder-access (not source)<br/>older ShadowPad variant"]:::adv
  C["<b>Capability</b><br/>5 sideload pairs<br/>32-bit ShadowPad<br/>EnumDesktopsA callback exec"]:::cap
  I["<b>Infrastructure</b><br/>(pre-deployment artefacts)"]:::inf
  V["<b>Victim</b><br/>(none yet — kit build)"]:::vic
  A -->|crafts| C
  C -->|staged at| I
{{< /mermaid >}}

**ATT&CK:** T1027 (Obfuscated Files), T1574.002 (DLL Side-Loading), T1112 (Modify Registry — payload storage).

{{< /timelineItem >}}

{{< timelineItem icon="envelope" header="Stage 3 — Delivery" badge="T1190" subheader="ProxyLogon RCE, AnyDesk handoff, React2Shell on Linux (low conf.)" md="true" >}}

Three delivery paths.

**Primary:** ProxyLogon (CVE-2021-26855 SSRF, CVE-2021-26857 insecure deserialisation, CVE-2021-26858 + CVE-2021-27065 post-auth arbitrary file write). Five years after Hafnium used the same chain, the long tail of unpatched Exchange is still wide enough that Trend observed -053 relying on it as primary.

**Secondary:** AnyDesk as the delivery channel in at least one intrusion. Trend can't say whether this is an alternative initial access vector or a later handoff from an earlier compromise — what matters operationally is the pattern: leverage a signed, EDR-tolerated RAT to walk ShadowPad onto the target.

**Tertiary, low-confidence:** Linux NOODLERAT delivery via CVE-2025-55182 React2Shell, with implants retrieved from `194.38.11.3:1790`.

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>same operator<br/>multi-channel"]:::adv
  C["<b>Capability</b><br/>ProxyLogon RCE chain<br/>AnyDesk handoff<br/>React2Shell (low conf.)"]:::cap
  I["<b>Infrastructure</b><br/>194.38.11.3:1790 staging<br/>AnyDesk relay (legitimate)"]:::inf
  V["<b>Victim</b><br/>Exchange (legacy builds)<br/>AnyDesk-allowed hosts<br/>vuln React2Shell"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|targets| V
{{< /mermaid >}}

**ATT&CK:** T1190 (Exploit Public-Facing Application), T1219 (Remote Access Software — AnyDesk).

{{< /timelineItem >}}

{{< timelineItem icon="bug" header="Stage 4 — Exploitation" badge="T1018" subheader="RCE under w3wp.exe; AD + Exchange recon via web shell" md="true" >}}

ProxyLogon SSRF + post-auth file-write gives RCE under the IIS worker `w3wp.exe`. Trend captured the operator running domain admin enumeration, `nltest /dclist`, `nslookup` against internal Exchange servers, `csvde.exe` for AD CSV export, and PowerView's `Get-DomainUser` — all under the web-shell process tree. They also dropped a 28 KB custom `DomainMachines.exe` that enumerates machines over LDAP and probes ports 139/445 (SMB), 80/443/8080/8443 (HTTP), 3389 (RDP), 5985/5986 (WinRM), 3306 (MySQL), 1433 (MSSQL), 88 (Kerberos).

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>hands-on-keyboard<br/>via web shell"]:::adv
  C["<b>Capability</b><br/>nltest / csvde / nslookup<br/>PowerView Get-DomainUser<br/>DomainMachines.exe LDAP"]:::cap
  I["<b>Infrastructure</b><br/>victim's Exchange / IIS<br/>w3wp.exe as process parent"]:::inf
  V["<b>Victim</b><br/>Active Directory<br/>internal Exchange + DCs<br/>visible from DMZ"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|targets| V
{{< /mermaid >}}

**ATT&CK:** T1190 (continued), T1059 (Command and Scripting Interpreter), T1018 (Remote System Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery).

{{< /timelineItem >}}

{{< timelineItem icon="download" header="Stage 5 — Installation" badge="T1505.003" subheader="GODZILLA web shells + ShadowPad loader + Scheduled Task M1onltor" md="true" >}}

Three persistence anchors layered.

**Web shells.** GODZILLA dropped under Exchange/IIS web roots (`C:\inetpub\wwwroot\aspnet_client\system_web\` and `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\`). Twelve filenames observed — `error.aspx`, `errorFE.aspx`, `signout.aspx`, `warn.aspx`, `data.aspx`, `page.aspx`, `TimeinLogout.aspx`, `timeout.aspx`, `charcode.aspx`, `tunnel.ashx`, `i.aspx`, `2.aspx`. The `.ashx` HTTP-handler variant is new for this cluster.

**ShadowPad loader** sideloaded into a legitimate signed binary in `C:\Users\Public` or `C:\ProgramData`, with the encrypted shellcode in `HKCU\Software\<ComputerName>\scode`.

**Scheduled Task `M1onltor`** runs the sideloaded loader every five minutes with highest privileges. That five-minute interval is what makes the `scode` registry value an effective Fleet *policy* — if it's there, it's running.

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>same operator<br/>sequential install"]:::adv
  C["<b>Capability</b><br/>GODZILLA web shells<br/>DLL-sideload loader<br/>Scheduled Task M1onltor"]:::cap
  I["<b>Infrastructure</b><br/>C:\\Users\\Public · C:\\ProgramData<br/>HKCU\\Software\\&lt;host&gt;\\scode<br/>Task Scheduler"]:::inf
  V["<b>Victim</b><br/>Exchange + IIS roots<br/>every host receiving ShadowPad"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|persists on| V
{{< /mermaid >}}

**ATT&CK:** T1505.003 (Server Software Component — Web Shell), T1574.002 (DLL Side-Loading), T1112 (Modify Registry), T1053.005 (Scheduled Task/Job).

{{< /timelineItem >}}

{{< timelineItem icon="cloud" header="Stage 6 — Command and Control" badge="T1071.001" subheader="Layered redundant tunnels — IOX + GOST + Wstunnel + custom tunnel-core" md="true" >}}

Operational redundancy is the load-bearing design. Multiple tunnel tools, all pointed at the same C2 — if one is detected, the others sustain the channel.

{{< figure src="images/c2-tunnel-architecture.svg" alt="C2 tunnel architecture diagram showing compromised hosts feeding into layered tunnel tools (IOX, GOST, Wstunnel, tunnel-core) and a parallel AnyDesk lane, all converging on three C2 endpoints" caption="One C2 host. Four tunnel implementations. The redundancy is the point — block any one and the operator still has the channel." >}}

- **IOX proxy.** Local accounts created with `LocalAccountTokenFilterPolicy=1` set to enable Pass-the-Hash from any local admin. Trend ties the registry-set to the IOX deployment context specifically — but the value itself is the **generic Microsoft UAC remote-restriction bypass** ([KB951016](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)). Plenty of legitimate tooling sets it.
- **GOST** as SOCKS5 + WebSocket tunnels to `96.9.125.227`.
- **Wstunnel** deployed as `wt.exe`, tunnelling SOCKS5 over HTTPS to the same `96.9.125.227`.
- **Renamed `tunnel-core.exe` → `code.exe`** invoked with parameter `client.toml`, talking to `96.9.125.227:8067`. The tool itself was not recovered.
- **AnyDesk** as a signed, EDR-friendly RAT.
- **`mdync.exe`** beaconing to `141.164.46.77`, dropped by `TosBtKbd.dll`.
- **NOODLERAT (Linux)** with C2 `check.office365-update.com` — domain registered 2025-11-19, low-confidence link.

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>parallel channels<br/>for operational redundancy"]:::adv
  C["<b>Capability</b><br/>IOX / GOST / Wstunnel<br/>tunnel-core (code.exe)<br/>AnyDesk / mdync / NOODLERAT"]:::cap
  I["<b>Infrastructure</b><br/>96.9.125.227:8067<br/>141.164.46.77 · 194.38.11.3:1790<br/>check.office365-update.com"]:::inf
  V["<b>Victim</b><br/>compromised hosts<br/>with 443/8067 egress"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|tunnels to/from| V
{{< /mermaid >}}

**ATT&CK:** T1071.001 (Application Layer — Web Protocols), T1090.001 (Internal Proxy), T1090.002 (External Proxy), T1219 (AnyDesk), T1071.004 (DNS — NOODLERAT C2).

{{< /timelineItem >}}

{{< timelineItem icon="skull-crossbones" header="Stage 7 — Actions on Objectives" badge="T1114.002" subheader="LSASS theft, DCSync, EWS mailbox export, RingQ defence-evasion" md="true" >}}

Three observed objective categories.

**Credential theft.** Mimikatz via `rundll32.exe` with `sekurlsa::logonpasswords` and `lsadump::sam`, spawned by `w3wp.exe`. Evil-CreateDump (a modified `create-dump.exe` retargeted at LSASS). `newdcsync` for DCSync attacks.

**Lateral movement.** WMIC for installing backdoors. Sharp-SMBExec (C# SMBExec). A custom RDP launcher named `smss.exe`. Web shells copied to additional internal Exchange servers over admin shares (`copy charcode.aspx \\<IP>\c$\inetpub\wwwroot\aspnet_client\system_web\`).

**Mailbox + IP exfiltration.** Iterative Exchange PowerShell — initial `Get-Mailbox` fails, operator adds `Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn`, refines to `Get-User`, layers in `userAccountControl` and `AccountDisabled` to identify high-value active accounts. A custom **`ExchangeExport`** tool then exports mailboxes via EWS. Trend notes this matches Microsoft's observation of Silk Typhoon (Hafnium). One observed exfil run produced a password-protected RAR of an executive's PST.

Defence evasion overlays the stage: **RingQ** packer for signature evasion, `net.exe` and PowerShell copied into `C:\ProgramData` with `$<RANDOM>.log` filenames to defeat process-name-based detection.

{{< mermaid >}}
graph LR
  classDef adv fill:#1a1a2e,stroke:#e94560,color:#fff
  classDef cap fill:#16213e,stroke:#0f3460,color:#fff
  classDef inf fill:#0f3460,stroke:#533483,color:#fff
  classDef vic fill:#533483,stroke:#e94560,color:#fff
  A["<b>Adversary</b><br/>long-term espionage<br/>mailbox + IP theft"]:::adv
  C["<b>Capability</b><br/>Mimikatz (rundll32)<br/>Evil-CreateDump · newdcsync<br/>Sharp-SMBExec · smss.exe<br/>ExchangeExport / EWS · RAR<br/>RingQ packer · $RANDOM.log"]:::cap
  I["<b>Infrastructure</b><br/>compromised DCs<br/>internal Exchange<br/>Stage-6 C2 channels"]:::inf
  V["<b>Victim</b><br/>executive mailboxes<br/>AD creds · KRBTGT (DCSync)<br/>IT consultancies → MoD pivots"]:::vic
  A -->|uses| C
  C -->|on| I
  I -->|exfils from| V
{{< /mermaid >}}

**ATT&CK:** T1003.001 (LSASS Memory), T1003.006 (DCSync), T1218.011 (Rundll32), T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1560.001 (Archive via Utility), T1114.002 (Remote Email Collection), T1036.005 (Match Legitimate Name).

{{< /timelineItem >}}

{{< /timeline >}}

## The -053 / -054 temporal overlap

One last frame before the queries. Trend Micro's Figure 1 in the report shows -053 and -054 sharing victims with up to eight months of temporal offset between the two clusters' activity. Independent exploitation of the same vulnerabilities — same toolkit overlap (Evil-CreateDump, IOX by SHA-256-identical binaries), same initial access vector, no operational coordination Trend could detect.

{{< mermaid >}}
gantt
  title SHADOW-EARTH-053 + -054 temporal overlap
  dateFormat YYYY-MM
  axisFormat %Y-%m
  section -054
    Initial Exchange compromise   :active, a1, 2024-10, 5M
    Re-exploitation              :crit,   a2, 2026-01, 3M
  section -053
    ShadowPad deployment          :active, b1, 2025-06, 9M
    Linux NOODLERAT (low conf.)  :crit,   b2, 2025-12, 1M
{{< /mermaid >}}

If you find -053 at a victim, assume -054 was there first. If you find -054, assume -053 may follow. The operational lesson: detection rules tuned to one cluster's toolkit will partially fire on the other's, and that's fine — investigate either signal as if it's both.

## Detection lenses — three behavioural axes, every query validated

The TTPs above collapse into three behavioural lenses for detection:

1. **Web shell + Exchange/IIS abuse** (Stages 3, 4, 5 — initial access through `w3wp.exe` LOLBIN spawns).
2. **ShadowPad persistence + layered tunnels** (Stages 5, 6 — sideload loader, registry shellcode, Scheduled Task, IOX/GOST/Wstunnel/AnyDesk).
3. **Credential theft + mailbox export** (Stage 7 — LSASS, DCSync, EWS PST export).

Every osquery query below was audited against the [current Fleet table schema](https://fleetdm.com/tables/). Reading the generic version of this detection set that's been circulating, I found a handful of bugs that would silently break the queries. The fixes are inline. Schema realities worth internalising first:

- **`file.sha256` does not exist.** Hashes come from the `hash` table joined on `path`.
- **`file.directory IN (...)` violates osquery's required-equality constraint** and is rejected at runtime. Use repeated `directory = '...'` clauses joined with `OR`.
- **`file_events` and `socket_events` are macOS + Linux only.** On Windows, use the NTFS publisher, `process_etw_events`, or `windows_events`. A copy-pasted `file_events` query against a Windows host returns zero rows silently, which reads as "no threat" if you don't know the platform asymmetry.
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

`file_events` is **macOS + Linux only** ([fleetdm.com/tables/file\_events](https://fleetdm.com/tables/file_events)). For Windows IIS FIM, set `enable_ntfs_event_publisher: true` in agent options and watch the NTFS event stream — there is no Windows equivalent of `file_events` in the standard osquery extension set. Define the `exchange_webroot` and `iis_webroot` categories under `file_paths:` in your agent config (snippet below).

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

Don't try to filter on `parent_name = 'w3wp.exe'` inside the query — `process_etw_events` doesn't expose parent metadata beyond `ppid` ([fleetdm.com/tables/process\_etw\_events](https://fleetdm.com/tables/process_etw_events)). Correlate to `w3wp` in your SIEM by joining on `(host_id, ppid)` against a companion `processes` query, or with the Sysmon EventID 1 stream via `windows_events`. Requires `enable_process_etw_events: true`. **High-FP without correlation** — `rundll32` and `cmd.exe` are noisy.

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

Six DLL/EXE names cover the four documented sideload pairs + the Toshiba loader. `mdync.exe` is the post-loader beaconer.

#### 2.2 ShadowPad shellcode in the registry (Windows)

```sql
SELECT path, key, name, type, mtime
FROM registry
WHERE path LIKE 'HKEY_USERS\%\Software\%\scode';
```

`HKEY_USERS\<SID>\Software\<ComputerName>\scode` is the osquery-visible form of `HKCU\Software\<ComputerName>\scode` across every loaded user hive. Make this a Fleet policy that fails on any returned row — there's no legitimate reason for a value named `scode` to exist directly under `HKCU\Software\<hostname>`.

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

Trend ties this registry-set to the operator's IOX deployment specifically, but as I noted in the seven-day plan, the value itself is the **generic Microsoft UAC remote-restriction bypass** (KB951016). Treat `1` as "explain why this is here" rather than auto-incident.

#### 2.5 Tunnel binaries by name and command line (Windows)

```sql
SELECT pid, name, path, cmdline, parent
FROM processes
WHERE name IN ('iox.exe','gost.exe')
   OR cmdline LIKE '%--listen socks%'
   OR cmdline LIKE '%client.toml%'
   OR cmdline LIKE '%wstunnel%';
```

`code.exe` and `wt.exe` are intentionally omitted from the `name` predicate — they collide with Visual Studio Code and Windows Terminal respectively, which would generate noise on every developer workstation. The `cmdline LIKE '%client.toml%'` branch catches the renamed `tunnel-core`/`code.exe` invocation Trend observed.

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

Requires Sysmon installed on the endpoint, `enable_windows_events_publisher: true` in Fleet agent options, and the Sysmon channel subscribed. Without Sysmon: zero rows. Document this dependency in your detection-engineering inventory — Mimikatz-via-rundll32 is the highest-confidence credential-theft signal in the report.

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

Requires Windows Script Block Logging enabled via GPO (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`) and `enable_powershell_events_subscriber: true` in agent options. The `cosine_similarity` column ([fleetdm.com/tables/powershell\_events](https://fleetdm.com/tables/powershell_events)) is a character-frequency anomaly score against osquery's built-in baseline — lower means more anomalous; add a row threshold like `cosine_similarity < 0.25` for an unsupervised fallback that catches scripts not in the IOC list.

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

`launchd.run_at_load` and `launchd.keep_alive` are text columns whose values aren't uniformly normalised across plists ([fleetdm.com/tables/launchd](https://fleetdm.com/tables/launchd)) — the dual predicate covers `'1'` and `'true'`. Not in the Trend report, but I include it because an operator with executive-mailbox access often pivots to laptops with the Exchange admin's session intact, and a LaunchAgent in `/Users/<user>/Library/LaunchAgents` is the macOS analogue of the `M1onltor` Scheduled Task.

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

## Required Fleet agent options

Several queries depend on evented tables and Windows publishers. Drop this into your Fleet agent options (or merge into an existing config) before running them:

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

Two prerequisites that live outside Fleet:

- **Sysmon** installed on every Windows host you care about, with a Mimikatz-aware config (the SwiftOnSecurity / olafhartong baselines both work).
- **PowerShell Script Block Logging** enabled via GPO. Without this, `powershell_events.script_text` is empty.

## What to make a Fleet policy vs a scheduled query

The detections split cleanly into two operational modes.

**Fleet policies (fail-on-any-row, page on failure).** These are the *should-not-exist* detections — a single row is a real finding worth waking someone up for.

- `1.1` GODZILLA web shell filenames in Exchange/IIS roots.
- `2.2` `scode` registry value under `HKCU\Software\<hostname>\`.
- `2.3` Scheduled Task named exactly `M1onltor`.
- `2.5` `iox.exe` / `gost.exe` running, or any process with `--listen socks` / `client.toml` / `wstunnel` in cmdline.
- `2.6` AnyDesk installed on a host labelled "Exchange servers" or "Domain Controllers".

**Scheduled queries (results into SIEM, correlate downstream).** High-volume behavioural queries that need correlation before alerting.

- `1.3` IIS worker spawning LOLBINs.
- `2.4` `LocalAccountTokenFilterPolicy = 1`.
- `2.7` Connections to published C2 infrastructure.
- `3.1` `rundll32` Mimikatz signatures.
- `3.2` Exchange PowerShell enumeration.
- `3.5` Linux web-tier unexpected outbound.

## Limits and caveats

A blog post is a poor place to hide caveats, so the load-bearing ones go here:

1. **Trend Micro's `141.164.46.77`, `96.9.125.227`, `194.38.11.3`, `check.office365-update.com` atomic IOCs will burn fast.** Use them, but build the behavioural detections (process tree, registry, scheduled task) as the durable layer. Static IOCs rotate; the placement and the loading mechanism don't.
2. **Trend's NOODLERAT attribution to SHADOW-EARTH-053 is explicitly *low confidence*.** If you see NOODLERAT on a Linux host, work it as a separate NOODLERAT incident first; the -053 link is supporting evidence, not the leading edge.
3. **No public attribution to a known named group exists for -053.** Kellermann's "younger sibling of the Typhoons" framing is editorial — Trend Micro itself says they found no strong overlap with any publicly reported cluster.
4. **`file_events` and `socket_events` are macOS + Linux only.** Don't read zero rows on Windows as "clean." Use `process_etw_events`, `windows_events`, and the `file` snapshot pattern on Windows.
5. **`process_etw_events` parent correlation cannot live inside a single osquery query.** Correlate downstream — in your SIEM, in Fleet's results pipeline, or against a companion `processes` snapshot keyed by `(host_id, ppid)`.
6. **`LocalAccountTokenFilterPolicy = 1` is not exclusive to -053 or to IOX.** It's a generic UAC bypass written by many lateral-movement toolkits. Treat it as a context-builder, not a standalone IOC.

## Downloads

The full validated query set, plus the agent-options snippet, as standalone artefacts:

| Artefact | Link |
|---|---|
| Windows query bundle | [`/code/se053-windows-queries.sql`](/dirtyfrag-blog/code/se053-windows-queries.sql) |
| Linux query bundle | [`/code/se053-linux-queries.sql`](/dirtyfrag-blog/code/se053-linux-queries.sql) |
| macOS query bundle | [`/code/se053-macos-queries.sql`](/dirtyfrag-blog/code/se053-macos-queries.sql) |
| Fleet agent options snippet | [`/code/se053-fleet-agent-options.yml`](/dirtyfrag-blog/code/se053-fleet-agent-options.yml) |

## Sources

| | |
|---|---|
| Primary report | [Trend Micro — *Inside Shadow-Earth-053: A China-Aligned Cyberespionage Campaign Against Government and Defense Sectors in Asia*](https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html), Daniel Lunghi + Lucas Silva, 30 Apr 2026 |
| Press coverage + Tom Kellermann interview | [*The Register* — *Chinese spy group caught lurking in Poland, Asia networks*](https://www.theregister.com/2026/04/30/chinese_spies_lurking_networks/), 30 Apr 2026 |
| Secondary summary | [Industrial Cyber — *SHADOW-EARTH-053 targets Asian government, defense, critical infrastructure via Exchange and IIS vulnerabilities*](https://industrialcyber.co/ransomware/shadow-earth-053-targets-asian-government-defense-critical-infrastructure-via-exchange-and-iis-vulnerabilities/) |
| Typhoon family context (companion read) | [CISA — Joint Cybersecurity Advisory AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a), August 2025 |
| ShadowPad background | [Trend Micro — Earth Alux espionage toolkit](https://www.trendmicro.com/en_us/research/25/c/the-espionage-toolkit-of-earth-alux.html) |
| Fleet table reference (used throughout) | [fleetdm.com/tables](https://fleetdm.com/tables/) — every query above footnoted to its specific table page |
| UAC remote-restriction reference | [Microsoft KB951016 — `LocalAccountTokenFilterPolicy`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction) |
