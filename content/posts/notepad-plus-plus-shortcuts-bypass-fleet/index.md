---
title: "Notepad++ trusted-directory bypass (GHSA-p58x-r3c9-x9p6): find it with Fleet, portable copies included"
date: 2026-06-10T09:00:00-04:00
draft: false
tags: ["fleet", "osquery", "windows", "vulnerability-management", "detection-engineering", "notepad-plus-plus", "portable-apps"]
categories: ["security-ops"]
description: "A High-severity Notepad++ advisory with no assigned CVE. How to find vulnerable installs and portable copies with Fleet and osquery, and a policy to track patch status continuously — because a VM scanner sees the installed program but misses the portable .exe."
summary: "GHSA-p58x-r3c9-x9p6 is a path-traversal bypass of the CVE-2026-48800 patch in Notepad++ v8.9.6.1, fixed in v8.9.6.2. It carries no CVE of its own, so vulnerability scanners that key on CVE catalogs may not flag it — and even when they do, they catch the registry-installed program while a portable notepad++.exe dropped in Downloads goes unseen. This post validates the advisory, then ships a Fleet/osquery identification query and a policy that fails when a vulnerable copy is present, installed or portable."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

> **The point of this writeup:** vulnerability management isn't CVE management — and it isn't installer management either. This advisory has no CVE, so catalog-driven scanners may stay quiet. And Notepad++ ships as a portable build, so a scanner reading the Windows registry sees the installed program but never the portable `notepad++.exe` someone unzipped into Downloads. Track the artifact (the binary and its version on disk), not just the catalog entry.

## At a glance

| | |
|---|---|
| **Advisory** | [GHSA-p58x-r3c9-x9p6](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-p58x-r3c9-x9p6) — "CVE-2026-48800 Bypass" |
| **CVE** | None assigned. CVE-2026-48800 is the *original* flaw this bypasses, not this advisory's own ID |
| **Severity** | High, CVSS 3.1 = 7.8 |
| **Affected** | Notepad++ v8.9.6.1 |
| **Patched** | Notepad++ v8.9.6.2 |
| **Weakness** | CWE-42 (path equivalence) — the advisory summary also references path traversal / CWE-59 |
| **Impact** | Arbitrary code execution from a poisoned `shortcuts.xml`, with no warning dialog |
| **Published** | 2026-05-31 by the Notepad++ maintainer (donho) |

## Executive summary

A High-severity Notepad++ advisory ([GHSA-p58x-r3c9-x9p6](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-p58x-r3c9-x9p6)) bypasses the fix for CVE-2026-48800. On v8.9.6.1, a crafted entry in `shortcuts.xml` runs an arbitrary executable without the security warning the patch was meant to show. The fix is v8.9.6.2.

Two facts make this awkward to track with conventional tooling. First, the advisory has no CVE of its own, so a scanner that matches on CVE catalogs may report nothing. Second, Notepad++ is commonly run as a portable build that never touches the Windows registry — so a scanner that enumerates installed programs misses portable copies entirely.

Recommended action: upgrade Notepad++ to v8.9.6.2 or later on every Windows host, and remove portable copies below that version. To find what you have and confirm the fix sticks, run the Fleet/osquery query below for a point-in-time inventory, and deploy the policy for continuous tracking. A policy result of **FAIL** means a vulnerable copy is present.

## What the advisory actually says

The CVE-2026-48800 patch added an `isInTrustedDirectory()` check in `Command::run()` (RunDlg.cpp) before Notepad++ calls `ShellExecute()`. The intent: only run executables that resolve under a trusted directory (`C:\Program Files\`, `C:\Program Files (x86)\`, `C:\Windows\System32\`, `C:\Windows\`), and warn otherwise.

The bug is that the check does not canonicalize the path first. It is a prefix match, so a path that *starts with* a trusted directory string passes — even when `..\..\` later in the path resolves the real target somewhere untrusted. The advisory documents two working bypasses:

- **Path traversal.** `C:\Windows\System32\..\..\Users\[USERNAME]\Downloads\mimikatz.exe` passes the prefix check and runs with no warning, while the direct path to the same binary is correctly blocked.
- **Trusted launcher.** `cmd.exe /c calc.exe` or `powershell.exe -ExecutionPolicy Bypass -Command ...` resolves to a binary that genuinely lives in `System32`, so the launcher runs with no warning and executes whatever it's told to.

`shortcuts.xml` lives in `%APPDATA%\Notepad++\`. Any process running as the user can write it; it can also be redirected with `notepad++.exe -settingsDir=...`, or poisoned through a synced profile directory (OneDrive, Dropbox). The fix ([commit ea15088](https://github.com/notepad-plus-plus/notepad-plus-plus/commit/ea1508855e9c4528f6198ce9d345f13cb759ebf4)) canonicalizes the path before the trusted-directory check.

One note on the CVSS data: the structured base metrics on the advisory read `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`, while the prose summary lists `PR:L/UI:N`. Both compute to 7.8. The values above use the structured block.

## Why a VM scanner isn't enough here

Two gaps, both worth saying out loud:

No CVE means catalog-driven detection has nothing to match. Tools that map installed software to NVD entries will not flag a host as vulnerable for an advisory that NVD doesn't list. You have to track this one by version.

Portable copies don't register. Notepad++ offers a portable build that runs from any folder and writes nothing to the registry. The osquery `programs` table — and most asset/VM scanners — read installed-program metadata from the registry. A portable `notepad++.exe` sitting in `Downloads`, `Desktop`, or a synced folder is invisible to that approach, even though it's just as exploitable. The Fleet docs even use Notepad++ as the canonical `programs` example, which is exactly why it's a useful reminder: the registry view is the installed view, not the on-disk view.

The fix for both gaps is the same: look at the binary on disk and read its version.

## Step 1 — identify what you have

This query reports Notepad++ on a Windows host whether it's installed or portable. The `file` rows cover the binary in the standard install paths plus common portable locations; the `processes` row catches a running portable copy whose path sits elsewhere.

```sql
SELECT 'file' AS src, path, file_version, product_version FROM file
WHERE path IN ('C:\Program Files\Notepad++\notepad++.exe',
               'C:\Program Files (x86)\Notepad++\notepad++.exe')
   OR path LIKE 'C:\Users\%\Downloads\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\Desktop\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\Documents\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\AppData\Local\%\notepad++.exe'
UNION ALL
SELECT 'proc' AS src, path, '' , '' FROM processes WHERE LOWER(path) LIKE '%notepad++.exe%';
```

Run it as a live query in Fleet across your Windows hosts. Rows with a `file_version` of `8.9.6.1` or lower are vulnerable; `8.9.6.2` and up are patched. A `proc` row with no matching `file` row points to a portable copy running from a path you haven't enumerated yet — follow up on those.

Download: [`/code/notepad-plus-plus-shortcuts-bypass-detect.sql`](/dirtyfrag-blog/code/notepad-plus-plus-shortcuts-bypass-detect.sql)

## Step 2 — track it continuously with a policy

A live query is a snapshot. To watch patch status over time, set it up as a Fleet policy. This policy passes only when neither a vulnerable installed program nor a vulnerable file is present. The version string is converted to a single sortable integer so the comparison is numeric, not lexical.

```yaml
policies:
  - name: "Notepad++ patched against CVE-2026-48800 bypass (GHSA-p58x-r3c9-x9p6)"
    platform: windows
    description: "Fails if Notepad++ <= 8.9.6.1 (or unreadable version) is installed or present as a portable copy. Advisory has no CVE; tracked by version."
    resolution: "Update Notepad++ to v8.9.6.2+. Remove portable copies below that version."
    query: |
      SELECT 1 WHERE
      NOT EXISTS (
        SELECT 1 FROM programs
        WHERE name LIKE 'Notepad++%'
          AND ( CAST(split(version,'.',0) AS INTEGER)*1000000000
              + CAST(split(version,'.',1) AS INTEGER)*1000000
              + CAST(split(version,'.',2) AS INTEGER)*1000
              + CAST(split(version,'.',3) AS INTEGER) ) < 8009006002
      )
      AND NOT EXISTS (
        SELECT 1 FROM file
        WHERE ( path LIKE 'C:\Program Files\Notepad++\notepad++.exe'
             OR path LIKE 'C:\Program Files (x86)\Notepad++\notepad++.exe'
             OR path LIKE 'C:\Users\%\Downloads\notepad++.exe'
             OR path LIKE 'C:\Users\%\Downloads\%\notepad++.exe'
             OR path LIKE 'C:\Users\%\Desktop\notepad++.exe'
             OR path LIKE 'C:\Users\%\Desktop\%\notepad++.exe'
             OR path LIKE 'C:\Users\%\Documents\notepad++.exe'
             OR path LIKE 'C:\Users\%\Documents\%\notepad++.exe' )
          AND ( CAST(split(file_version,'.',0) AS INTEGER)*1000000000
              + CAST(split(file_version,'.',1) AS INTEGER)*1000000
              + CAST(split(file_version,'.',2) AS INTEGER)*1000
              + CAST(split(file_version,'.',3) AS INTEGER) ) < 8009006002
      );
```

The threshold `8009006002` encodes v8.9.6.2: `8·10⁹ + 9·10⁶ + 6·10³ + 2`. A copy at 8.9.6.1 encodes to `8009006001`, which is below the threshold, so the policy fails. A result of **FAIL** means at least one vulnerable copy — installed or portable — is on the host.

Download: [`/code/notepad-plus-plus-shortcuts-bypass-policy.yml`](/dirtyfrag-blog/code/notepad-plus-plus-shortcuts-bypass-policy.yml)

## Validation and limitations

Both queries were checked against the current Fleet/osquery schema. The columns used — `file.path`, `file.file_version`, `file.product_version`, `processes.path`, `programs.name`, `programs.version` — all exist and are `text` type. The `split()` function is available in osquery SQL. The version arithmetic is correct for the v8.9.6.2 boundary.

Three honest limitations to size before you rely on this:

- **Version strings are assumed to have four parts.** The integer math reads four components (`8.9.6.2`). If a copy ever reports a three-part version (`8.9.6`), the missing fourth `split` returns an empty string, which casts to `0`, producing `8009006000` — below the threshold and a false **FAIL**. Notepad++ normally reports four parts, but check your fleet's actual `file_version` and `programs.version` values before treating a single failing host as real.
- **Portable paths are a heuristic.** The file checks cover the standard install directories plus `Downloads`, `Desktop`, `Documents`, and `AppData\Local`. A portable copy elsewhere (for example `C:\Tools\npp\`) won't be caught by the file branch — though the identification query's `processes` branch will catch it if it's running. The osquery `file` table also expands roughly one directory level per `%` in a `LIKE`, so very deep portable paths need explicit patterns. Add paths that match how your users actually store portable apps.
- **Unreadable versions fail closed.** If Notepad++ is present but its version can't be read, the policy treats it as vulnerable. That's deliberate — better a false **FAIL** to investigate than a silent miss — but it does mean a permissions or file-lock issue can surface as a failing host.

## Remediation

1. Upgrade Notepad++ to **v8.9.6.2** or later on all Windows hosts.
2. Remove portable copies below v8.9.6.2. The identification query lists their paths.
3. Keep the policy enabled so regressions — a user re-downloading an old portable build — show up as a fresh **FAIL**.

For defense in depth, treat writes to `%APPDATA%\Notepad++\shortcuts.xml` and Notepad++ launches with a `-settingsDir=` argument pointing at a non-local path as signals worth alerting on; both appear in the advisory's attack scenarios.

## Sources

- Notepad++ security advisory GHSA-p58x-r3c9-x9p6, "CVE-2026-48800 Bypass" — <https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-p58x-r3c9-x9p6> (affected/patched versions, CVSS, CWE, bypass detail, attack scenarios; CVE field reads "No known CVE").
- Fix commit ea15088 — <https://github.com/notepad-plus-plus/notepad-plus-plus/commit/ea1508855e9c4528f6198ce9d345f13cb759ebf4>.
- Fleet osquery schema (`file`, `processes`, `programs` tables) — <https://fleetdm.com/tables>, verified 2026-06-10.
