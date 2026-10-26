---
title: "HTTP2Shell (CVE-2026-111497): Hunt Vulnerable Brotli Copies with Fleet"
date: 2026-10-26T14:00:00-04:00
draft: false
tags: ["fleet", "osquery", "brotli", "nodejs", "bun", "envoy", "python", "macos", "windows", "linux", "detection-engineering", "cve-2026-111497"]
categories: ["security-ops"]
description: "Short brief on CVE-2026-111497, the Brotli decoder overflow behind HTTP2Shell, and six Fleet queries that find every vulnerable copy: distro packages, Homebrew, Node .pkg receipts, nvm/Volta/fnm binaries, Python wheels, Windows installs, and the processes actually listening on the network."
summary: "CVE-2026-111497 is a buffer overflow in Google's Brotli decoder (1.0.3 to 1.2.0) that is compiled into Node.js, Bun, Envoy, Python Brotli wheels, .NET and the browsers. A crafted Content-Encoding: br body reaches it with no login. The upstream fix is tiny; finding every bundled copy is the work. This post ships six Fleet queries with version logic that does not trust SQLite string comparison, a policy pattern, and what the queries found on a real fleet (hint: Pillow bundles libbrotli 1.2.0)."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

{{< alert "circle-info" >}}
**TL;DR.** CVE-2026-111497 (CVSS 4.0 score 9.2) is a Brotli decoder overflow, not an HTTP/2 bug. Anything that decodes `Content-Encoding: br` with Brotli 1.0.3 to 1.2.0 is exposed: Node.js, Bun, Envoy, Python `Brotli`/`brotlicffi`, .NET, Electron. Check Fleet's Software page first, then run the [six queries](#detect-six-fleet-queries). Download all of them as one file: [http2shell-fleet-queries.sql](/dirtyfrag-blog/code/http2shell-fleet-queries.sql).
{{< /alert >}}

## What it is

The bug lives in `c/dec/decode.c` of Google's Brotli library. When the decoder hits a block switch it cannot complete, vulnerable versions keep decoding instead of stopping. A crafted stream then writes past a small buffer into neighbouring decoder state. The upstream fix ([google/brotli commit 0ed4268](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)) makes it stop on the first format error.

Two ways in, both unauthenticated:

- **Inbound.** A server decompresses a request body sent with `Content-Encoding: br`. Express 5 does this by default through `express.json()`.
- **Outbound.** An app fetches a Brotli response from a server the attacker controls. Node.js `fetch()`, Python `requests`/`httpx`/`aiohttp` (when `Brotli` or `brotlicffi` is installed) decode it automatically.

Imperva reported code execution on the stock Node.js 24.22.0 Linux arm64 image. Other researchers got crashes. Not in CISA KEV as of 26 October. Full write-up with the per-product table: [Tanium's post](https://www.tanium.com/blog/http2shell-find-and-fix-vulnerable-brotli-copies-with-tanium).

{{< figure src="images/vulndash-cve.png" alt="Vulnerability dashboard page for CVE-2026-111497 showing EPSS 32.78 percent, one affected host, two affected software entries, SSVC decision Attend with high exploitability, and MITRE ATT&CK mappings T1190 Exploit Public-Facing Application and T1499 Endpoint Denial of Service" caption="SSVC says Attend. EPSS 32.78% four days after publication is high for a bug with no confirmed in-the-wild exploitation." >}}

## Fixed versions

| Component | Vulnerable | Fixed |
|---|---|---|
| Google Brotli | 1.0.3 to 1.2.0 | 1.0.10, 1.1.1, 1.2.1 |
| Node.js | 22.x, 24.x, 26.x before fix; 20.x and older, 23.x, 25.x are EOL | [22.23.4](https://nodejs.org/en/blog/release/v22.23.4), [24.22.1](https://nodejs.org/en/blog/release/v24.22.1), [26.12.1](https://nodejs.org/en/blog/release/v26.12.1) |
| Bun | 1.0.21 to 1.4.3 | [1.4.4](https://github.com/oven-sh/bun/releases/tag/bun-v1.4.4) |
| PyPI `Brotli` / `brotlicffi` | 1.0.3 to 1.2.0 / up to 1.2.0.x | [1.2.1](https://pypi.org/project/Brotli/1.2.1/) / [1.2.1.0](https://pypi.org/project/brotlicffi/1.2.1.0/) |
| Envoy / Istio | Brotli decompressor enabled | 1.40.0, 1.39.3, 1.38.6, 1.37.8 / 1.31.2, 1.30.6 |
| Chrome, Edge, Firefox, Electron | pre-148 / pre-150 / Electron 41 and older | 148+, 150 (ESR 140.10, 115.35), Electron 42+ |
| Ubuntu, RHEL, SUSE, AL2023, Fedora 43 to 45 brotli; Ubuntu/RHEL nodejs; Kibana; .NET | all | **no fix yet** as of 24 October |

Two traps. A patched Node.js still reports `process.versions.brotli` as 1.1.0 or 1.2.0, so never grade Node by its Brotli string. Distros backport without bumping the upstream number (Debian 12 is fixed in `brotli 1.0.9-2+deb12u1`), so grade distro packages against the vendor advisory, not the version.

## Step 0: Fleet already knows most of it

Fleet inventories `deb_packages`, `rpm_packages`, `homebrew_packages`, `apps`, `programs`, `python_packages` and `npm_packages` every hour. Open **Software**, search `brotli`, `node`, `bun`, `envoy`. Open **Vulnerabilities**, search `CVE-2026-111497`; the match lands once NVD publishes CPE configuration for it.

{{< figure src="images/vulndash-row.png" alt="Vulnerability list row for CVE-2026-111497 with status Missing, EPSS 32.8 percent, SSVC Attend, published and modified 10/22/2026, one affected host" caption="Inventory gets you the row. The queries below get you the copies inventory cannot see." >}}

The queries exist for what inventory misses: nvm, Volta and fnm binaries, macOS `.pkg` installs, bundled DLLs, wheels that vendor `libbrotli`, and which of those copies is actually reachable from the network.

## Detect: six Fleet queries

Every query is in [http2shell-fleet-queries.sql](/dirtyfrag-blog/code/http2shell-fleet-queries.sql). Scope each to the platform named in its heading.

**Why the version logic looks odd.** SQLite compares version strings as text: `'1.0.9' < '1.0.10'` is false, `'24.9.0' > '24.22.1'` is true. The queries never use `<` or `>` on a version. Brotli has exactly nine vulnerable releases, so it is an `IN` list. Node.js and Bun are split into major, minor and patch with `CAST`, which keeps the leading digits (`'22.1-1nodesource1'` casts to `22`), and compared as a number.

### 1. Linux: brotli and nodejs packages

```sql
WITH pk AS (
  SELECT name, version, 'deb' AS src FROM deb_packages
  WHERE name LIKE '%brotli%' OR name = 'nodejs'
  UNION ALL
  SELECT name, version || '-' || release, 'rpm' FROM rpm_packages
  WHERE name LIKE '%brotli%' OR name = 'nodejs'
),
k AS (
  SELECT *, CAST(version AS INT) AS maj,
    CAST(substr(version, instr(version,'.')+1) AS INT) AS mnr,
    CAST(substr(substr(version, instr(version,'.')+1), instr(substr(version, instr(version,'.')+1),'.')+1) AS INT) AS pat
  FROM pk
)
SELECT name, version, src,
  CASE WHEN name <> 'nodejs' THEN 'REVIEW-vs-advisory'
       WHEN (maj=22 AND mnr*1000+pat>=23004) OR (maj=24 AND mnr*1000+pat>=22001)
         OR (maj=26 AND mnr*1000+pat>=12001) OR maj>26 THEN 'FIXED'
       ELSE 'VULNERABLE' END AS status
FROM k;
```

`deb_packages.version` already carries the Debian revision; `rpm_packages` keeps `release` separate, so it is joined on.

### 2. macOS: Homebrew and Node.js .pkg receipts

```sql
WITH src AS (
  SELECT name, version, path AS location FROM homebrew_packages
  WHERE name = 'brotli' OR name LIKE 'node%' OR name IN ('bun','envoy')
  UNION ALL
  SELECT package_id, version, location FROM package_receipts
  WHERE package_id LIKE 'org.nodejs.node%'
),
k AS (
  SELECT *, ltrim(version,'v') AS v FROM src
),
n AS (
  SELECT name, version, location, CAST(v AS INT) AS maj,
    CAST(substr(v, instr(v,'.')+1) AS INT) AS mnr,
    CAST(substr(substr(v, instr(v,'.')+1), instr(substr(v, instr(v,'.')+1),'.')+1) AS INT) AS pat
  FROM k
)
SELECT name, version, location,
  CASE WHEN name = 'brotli' AND version IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
       WHEN name = 'brotli' THEN 'FIXED'
       WHEN name = 'bun' AND maj*1000000+mnr*1000+pat BETWEEN 1000021 AND 1004003 THEN 'VULNERABLE'
       WHEN name = 'bun' THEN 'FIXED'
       WHEN name = 'envoy' THEN 'REVIEW'
       WHEN (maj=22 AND mnr*1000+pat>=23004) OR (maj=24 AND mnr*1000+pat>=22001)
         OR (maj=26 AND mnr*1000+pat>=12001) OR maj>26 THEN 'FIXED'
       ELSE 'VULNERABLE' END AS status
FROM n;
```

`package_receipts` catches the installer from nodejs.org (`org.nodejs.node.pkg`), which no package manager table sees.

### 3. All platforms: Python Brotli wheels, per user

```sql
SELECT u.username, p.name, p.version, p.path,
  CASE
    WHEN lower(p.name) = 'brotli' AND p.version IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
    WHEN lower(p.name) = 'brotlicffi' AND substr(p.version,1,5) IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
    WHEN lower(p.name) = 'brotlipy' THEN 'REVIEW'
    ELSE 'FIXED' END AS status
FROM users u CROSS JOIN python_packages p USING (uid)
WHERE lower(p.name) IN ('brotli','brotlicffi','brotlipy');
```

The `CROSS JOIN users ... USING (uid)` is what makes `python_packages` walk every user's site-packages and venvs instead of only the system interpreter.

### 4. macOS/Linux: Node and Bun outside package managers

```sql
SELECT path, symlink_target_path, size, datetime(mtime,'unixepoch') AS modified FROM file
WHERE path IN ('/usr/bin/node','/usr/local/bin/node','/opt/homebrew/bin/node','/usr/local/bin/bun','/home/linuxbrew/.linuxbrew/bin/node')
   OR path LIKE '/Users/%/.nvm/versions/node/%/bin/node'
   OR path LIKE '/home/%/.nvm/versions/node/%/bin/node'
   OR path LIKE '/Users/%/.volta/tools/image/node/%/bin/node'
   OR path LIKE '/home/%/.volta/tools/image/node/%/bin/node'
   OR path LIKE '/Users/%/Library/Application Support/fnm/node-versions/%/installation/bin/node'
   OR path LIKE '/home/%/.local/share/fnm/node-versions/%/installation/bin/node'
   OR path LIKE '/Users/%/.bun/bin/bun'
   OR path LIKE '/home/%/.bun/bin/bun';
```

The Node version is in the folder name for nvm, Volta and fnm. For `/usr/local/bin/node`, `symlink_target_path` usually points into one of those folders and gives the version for free.

### 5. Windows: Node.js, Bun and the .NET native DLL

```sql
SELECT 'program' AS src, name, version, install_location AS path FROM programs
WHERE name LIKE 'Node.js%' OR name LIKE '%Bun%'
UNION ALL
SELECT 'file', filename, product_version, path FROM file
WHERE path = 'C:\Program Files\nodejs\node.exe'
   OR path LIKE 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App\%\System.IO.Compression.Native.dll'
   OR path LIKE 'C:\Users\%\.bun\bin\bun.exe'
   OR path LIKE 'C:\Users\%\AppData\Roaming\nvm\%\node.exe';
```

.NET has no vendor statement yet. Inventory it now so the day Microsoft ships a fix you already know where it goes.

### 6. All platforms: who is actually reachable

```sql
WITH lp AS (
  SELECT DISTINCT pid, port, address FROM listening_ports
  WHERE address NOT IN ('127.0.0.1','127.0.1.1','::1','') AND port > 0
)
SELECT DISTINCT p.pid, p.name, p.path, lp.port, lp.address,
  (SELECT path FROM process_memory_map m WHERE m.pid = p.pid AND m.path LIKE '%brotli%' LIMIT 1) AS brotli_lib
FROM lp JOIN processes p USING (pid)
WHERE lower(p.name) IN ('node','node.exe','bun','bun.exe','envoy','envoy.exe','dotnet','dotnet.exe','nginx','java')
   OR brotli_lib IS NOT NULL;
```

Two things make this cheap enough to run fleet-wide. `process_memory_map` is only read for pids that are listening, never for every process. And the brotli lookup is a `LIMIT 1` subquery, so it stops at the first hit. Statically linked decoders (Node, Bun) never show up as a library; that is what queries 1 to 5 are for.

{{< figure src="images/fleet-live-query.webp" alt="Fleet live query results from 33 hosts, 85 rows: two vLLM worker python3.12 processes on host automater with brotli_lib set to pillow.libs/libbrotlicommon-53534446.so.1.2.0, plus java processes from wazuh-indexer and OpenJDK, and nginx on fleetdm-server, each with pid, listening port and address" caption="Query 6 on 33 hosts. The only brotli library found mapped into a listening process came from a Pillow wheel, not from any package named brotli." >}}

**What it found on 33 hosts.** The vLLM worker processes on one host had `pillow.libs/libbrotlicommon-53534446.so.1.2.0` mapped. The Pillow wheel vendors its own `libbrotli` 1.2.0. No package named `brotli` on that host, no `python_packages` row for it, no Fleet inventory hit. Only the memory map shows it. The Java rows (Wazuh indexer and other JVM services) are listed for review because Netty stacks can pull in `brotli4j` (fixed in 1.24.0). Nginx is listed because `ngx_brotli` links `libbrotlidec`; the empty `brotli_lib` column says this build does not.

## Policy

Wrap any status query so the host fails while a `VULNERABLE` row exists. One policy per platform, same shape:

```sql
SELECT 1 FROM os_version WHERE NOT EXISTS (
  SELECT 1 FROM ( <query 1, 2 or 3 here> ) WHERE status = 'VULNERABLE'
);
```

## Fix

- Update OS packages where a fix exists, then restart the processes still holding the old library (query 6 shows which).
- Update owner-managed copies: nvm, fnm, Volta, Homebrew, Python lockfiles, Bun executables, container images. `bun build --compile` binaries must be rebuilt.
- Until then: reject `Content-Encoding: br` at the WAF or ingress; in Express 5 set `express.json({ inflate: false })` (also on `urlencoded()`, `text()`, `raw()`); remove the Brotli decompressor filter from Envoy and Istio; uninstall `Brotli`/`brotlicffi` from Python environments that only need it for outbound fetches.

## Sources

- [Tanium: HTTP2Shell, find and fix vulnerable Brotli copies](https://www.tanium.com/blog/http2shell-find-and-fix-vulnerable-brotli-copies-with-tanium)
- [NVD: CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497)
- [Node.js 24.22.1 security release](https://nodejs.org/en/blog/release/v24.22.1)
- [google/brotli fix commit 0ed4268](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
- osquery tables: [deb_packages](https://fleetdm.com/tables/deb_packages), [rpm_packages](https://fleetdm.com/tables/rpm_packages), [homebrew_packages](https://fleetdm.com/tables/homebrew_packages), [package_receipts](https://fleetdm.com/tables/package_receipts), [python_packages](https://fleetdm.com/tables/python_packages), [file](https://fleetdm.com/tables/file), [programs](https://fleetdm.com/tables/programs), [listening_ports](https://fleetdm.com/tables/listening_ports), [process_memory_map](https://fleetdm.com/tables/process_memory_map)
