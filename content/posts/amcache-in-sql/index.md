---
canonical: "https://karmine05.github.io/dirtyfrag-blog/posts/amcache-in-sql/"
meta-article:modified_time: "2026-09-21T09:45:00-04:00"
meta-article:published_time: "2026-09-21T09:45:00-04:00"
meta-article:section: posts
meta-article:tag: Security-Ops
meta-author: Dhruv Majumdar
meta-description: "osquery has had no Amcache table since 2020. A new extension parses the hive in place, while locked, on a live Windows host and serves it as seven SQL tables. Seven live queries on a Windows 11 Pro box, and what each one is for in detection and IR."
meta-keywords: amcache,amcache.hve,osquery,fleet,windows,dfir,incident-response,threat-hunting,shimcache,byovd,usb-forensics,registry-hive,security-ops
meta-og:description: "osquery has had no Amcache table since 2020. A new extension parses the hive in place, while locked, on a live Windows host and serves it as seven SQL tables. Seven live queries on a Windows 11 Pro box, and what each one is for in detection and IR."
meta-og:locale: en
meta-og:site_name: "karmine's notes"
meta-og:title: "The Amcache gap, closed: seven SQL tables for live Windows DFIR"
meta-og:type: article
meta-og:url: "https://karmine05.github.io/dirtyfrag-blog/posts/amcache-in-sql/"
meta-twitter:card: summary_large_image
meta-twitter:description: "Seven live queries on a Windows 11 Pro box, real results, and what each table is for in detection and IR."
meta-twitter:title: "The Amcache gap, closed: seven SQL tables for live Windows DFIR"
title: "The Amcache gap, closed: seven SQL tables for live Windows DFIR"
slug: amcache-in-sql
date: "2026-09-21T09:45:00-04:00"
categories:
  - Security-Ops
tags:
  - Amcache
  - Osquery
  - Fleet
  - Windows
  - DFIR
  - Incident-Response
  - Threat-Hunting
  - Registry
  - ShimCache
  - BYOVD
  - Security-Ops
showTableOfContents: true
---

> **One sentence:** Windows writes a rolling inventory of every executable, driver and device it has ever seen, osquery could not read that inventory until this week, and seven new SQL tables turn it into a live DFIR surface.

|                  |                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **The gap**      | Amcache.hve holds executable, driver and device history that only becomes readable at reboot (shimcache) or after imaging (forensics) |
| **The fix**      | A Fleet/osquery extension that parses the hive in place, while locked, and serves seven SQL tables                                    |
| **The surface**  | Executables, installed programs, shortcuts, driver binaries, driver packages, PnP devices, device containers                          |
| **The proof**    | Seven live queries on a Windows 11 Pro workstation, 2026-09-21 09:45 local, hive parsed in the same second as each query             |
| **The caveat**   | Amcache records that the appraiser *saw* a file. It is not proof of execution, and Windows 11 fills in half of every record          |

## The gap, in one incident

02:00, and a hash from your intel feed flags a file. The question is which of your twelve thousand endpoints has ever run it, and you want the answer before the operator at each desk wakes up and keeps working.

`processes` returns what is running right now. The thing you are hunting exited weeks ago. `shimcache`, the long-standing fallback, holds the answer but flushes it to disk only on reboot, and rebooting twelve thousand machines to answer one question destroys the volatile evidence you would want if any of them comes back positive. The honest options were: wait for the next reboot cycle and hope, or pick the handful of hosts you can justify pulling offline, image them, and run a forensics tool over the hive by hand. Both answer the question days late, and the second answers it for a handful of machines instead of the fleet.

The file with the answer sat on every one of those machines the entire time: `C:\Windows\AppCompat\Programs\Amcache.hve`. The request for an osquery table has been open since 2020 ([osquery/osquery#6639](https://github.com/osquery/osquery/issues/6639)), asked again in 2025 ([fleetdm/fleet#31103](https://github.com/fleetdm/fleet/issues/31103)), and until now the answer on Windows was shimcache or nothing.

{{< figure src="images/gap-0200.svg" nozoom="true" alt="The 02:00 IOC question against three answer sources: processes only sees what is running now and misses the target, shimcache holds the answer but writes it only at reboot which costs days, and the new amcache tables are written continuously and read in place while locked, answering in seconds across the whole fleet" caption="The 02:00 question, three answer sources. `processes` misses because the target exited weeks ago. `shimcache` answers days late, at reboot, and rebooting the fleet destroys the volatile evidence you would want if any host comes back positive. The amcache tables answer in seconds, fleet-wide, on hosts that stay up." >}}

## What Amcache is, and why the file sat there unread

The Microsoft Compatibility Appraiser keeps an inventory of the machine: SHA-1 and full path for executables it has seen, with publisher and PE metadata, driver binaries and packages, and every Plug and Play device ever enumerated. It writes continuously rather than at shutdown, so the inventory is current at the moment you ask, which is the property that makes mid-incident queries meaningful.

The file was unreadable for years for three specific reasons, and the extension's design is a direct answer to each:

1. **It is a registry hive, not a registry key.** osquery's `registry` table reads keys from the live tree. It cannot open an arbitrary hive file at all, so the appraiser's inventory was outside osquery's reach by construction.
2. **The appraiser holds the hive open, often mid-write.** A plain `open()` fails with a sharing violation. The extension falls back to a raw, read-only read of the NTFS volume (`\\.C:`), and when the hive is mid-transaction it replays `Amcache.hve.LOG1` and `.LOG2` in memory.
3. **Forensics tooling expects an offline copy.** Everything else on the market copies the file or reboots the machine first. The extension never writes, never shells out, never opens a socket, and creates no temporary files.

{{< figure src="images/read-path.svg" nozoom="true" alt="Read path for a locked Amcache.hve: an ordinary open first, a read-only raw NTFS read of the volume when the appraiser holds the hive open, in-memory replay of LOG1 and LOG2 when the hive is mid-write, a single parse that fails at thirty seconds instead of hanging, and seven SQL tables cached for five minutes so repeat queries do no I/O" caption="The read path, in order. The raw-volume fallback fires only after a genuine sharing violation, and it opens `\\.C:` read-only, touches exactly one path, and never copies the file. A join across the seven tables inside the five-minute cache window is one read and one parse; a repeat query does no I/O at all." >}}

One operational note before the queries: when the raw path fires, your EDR detects a privileged read-only volume handle and raises a flag on it. It happens only after a genuine sharing violation on the ordinary open, and it touches exactly one path. If your EDR flags it, allow-list the extension by Authenticode publisher or by the SHA-256 in the release's `SHA256SUMS`.

## The seven tables

| Table                              | Rows are                                             | Key columns                                          |
| ---------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| `amcache_application_files`        | executables the appraiser has inventoried            | `path`, `sha1`, `program_id`                          |
| `amcache_applications`             | installed programs                                   | `program_id`, `name`, `publisher`                     |
| `amcache_application_shortcuts`    | Start Menu shortcuts                                 | `path`, `target_path`, `program_id`                   |
| `amcache_driver_binaries`          | driver files                                         | `path`, `sha1`, `service`, `inf`                      |
| `amcache_driver_packages`          | DriverStore packages                                 | `inf`, `provider`, `class`                            |
| `amcache_device_pnp`               | devices ever enumerated                              | `device_instance_id`, `container_id`, `sha1`          |
| `amcache_device_containers`        | the physical device behind a set of PnP interfaces   | `container_id`, `friendly_name`                       |

Crisp, one line each:

- **`amcache_application_files`** is the workhorse: every executable the appraiser has seen, with path, SHA-1, publisher, product, and version metadata. Tens of thousands of rows on a normal workstation, and the table every other question in this post leans on.
- **`amcache_applications`** holds the installed programs keyed by the same `program_id`. It is the join target for the "no installer behind it" question.
- **`amcache_application_shortcuts`** maps Start Menu shortcuts to their targets. Useful when the question is what a user actually launched, and where the launch landed.
- **`amcache_driver_binaries`** holds every driver file with `inbox`, `signed` and `kernel_mode` flags. This is the bring-your-own-vulnerable-driver table.
- **`amcache_driver_packages`** is the DriverStore view: which INF installed what, and under which provider.
- **`amcache_device_pnp`** holds every device Windows has ever enumerated on the machine, with `first_install_time`. Devices persist after removal, which makes this a history, not an inventory.
- **`amcache_device_containers`** collapses the PnP rows that belong to one physical device into a single row with a friendly name. One monitor lands as multiple PnP rows, and the container is what a human recognizes.

Two semantics worth knowing before you read the results below. The `sha1` columns come from the hive's `FileId` and `DriverId` fields, not from `ProgramId`, which is a name/version/publisher digest and not a file hash. And a value the appraiser never wrote is never guessed at: text columns return an empty string, numeric columns return `NULL`. Every `*_time` column is unix epoch seconds, decoded as UTC.

{{< figure src="images/table-map.svg" nozoom="true" alt="Map of the seven amcache SQL tables served from one in-place parse of Amcache.hve: three executable tables joined on program_id, two driver tables, two device tables joined on container_id, plus joins into the rest of osquery on path, image and program_id" caption="The seven tables, one parse. `program_id` connects the executable trio; `container_id` folds PnP rows into one physical device; `sha1` resolves a device to its driver binary. Because they are SQL, all three families join to `authenticode`, `hash`, `drivers` and `programs` in the same statement, and the parse happens once, not seven times." >}}

## One machine, seven questions

The extension ran on a Windows 11 Pro workstation (a Micro-Star Aegis desktop, i9-14900F) under a plain `osqueryi` with the extension loaded directly: no Fleet, no daemon, no agent options. Each query below is a one-liner from that session, and each result is the real output, trimmed. The hive parsed in the same second as each query, and the appraiser was not holding it open, so this run did not exercise the raw-volume fallback:

```text
2026/09/21 09:45:16 amcache: hive parsed (raw volume read: false, transaction logs replayed: false)
```

### Q1: what has this machine run that is not provably signed

The first question a defender asks, and the one that exercises the join: Amcache says what the appraiser saw, osquery's `authenticode` table says what Windows can actually verify, and the join lands on the difference.

```sql
SELECT f.path, f.sha1, a.result
FROM amcache_application_files f
JOIN authenticode a ON a.path = f.path
WHERE a.result != 'trusted'
  AND f.path NOT LIKE 'c:\windows\%';
```

```text
| path                                                                              | sha1                             | result  |
+-----------------------------------------------------------------------------------+----------------------------------+---------+
| c:\program files\7-zip\7z.exe                                                     |                                  | missing |
| c:\users\dhruv\anaconda3\library\bin\adig.exe                                     |                                  | missing |
| c:\users\dhruv\downloads\ultimate_ai_influencer_comfyui_installer-08-06-25\...    |                                  |         |
|   comfyui\venv\scripts\accelerate.exe                                             | bcb1662a55d1aaa6ca5d790b4446d5c31fd9d4fd | missing |
| c:\program files\git\usr\bin\bash.exe                                             | 948a5dd008e75bef11bbe75509bfc86a009da857 | untrusted |
| c:\program files\git\usr\bin\sh.exe                                               |                                  | untrusted |
... 1205 more rows ...
1215 rows: 1213 missing, 2 untrusted
```

Read it in four passes.

The two `untrusted` rows are Git for Windows' own `bash.exe` and `sh.exe`. That is baseline, not an incident: Git ships its own copies, and Authenticode does not trust them. A query this broad always returns a baseline on every machine, and the value of running it is that your fleet's baseline becomes a measured thing you can diff against.

The ComfyUI rows are the interesting shape. A downloaded installer under `c:\users\dhruv\downloads` unpacked a Python venv, and every script in it is unsigned, but every row also carries a real SHA-1 that can go straight into an intel feed. Forty-plus executable scripts from one download, each addressable by hash, on a machine that is still powered on.

The empty `sha1` cells are Windows 11, not the extension: 934 of the 1,215 rows here carry a path and no hash. Windows 10 and Server populate both fields on every record, and the README's rule of thumb for Win11 is three in four rows are hash-only stubs. A hash sweep returns rows with empty paths, and a path lookup returns rows with an empty hash. Build your detections around that, not around it.

Finally, the warning stream. This query logged 326 authenticode failures while it ran: 307 for the "Failed to query the Authenticode signature information" error and 19 for "The publisher information could not be found." The bulk of the 307 are Store apps under `C:\Program Files\WindowsApps`, whose trust lives in the package catalog rather than an embedded signature. osquery drops those rows after the verdict is decided, so an absent path in the output means *unknown*, not *clean*. A returned row is a real hit, and an absent one is a gap to close with another signal. The join also does real work: `authenticode` verifies on disk, and this query took about 90 seconds of wall time on the box. Not free, but one query instead of a per-file loop.

### Q2: bring-your-own-vulnerable-driver, the strict version

```sql
SELECT b.path, b.driver_name, b.sha1, b.driver_version, b.service
FROM amcache_driver_binaries b
WHERE b.inbox = 0 AND b.signed = 0 AND b.kernel_mode = 1;
```

```text
0 rows
```

Zero rows is a result. The machine carries no kernel driver that did not ship with Windows and was not signed at inventory time. On a fleet, this is the query that tells you which hosts are worth imaging: the ones that return rows.

### Q3: drivers Amcache remembers that the live driver list has forgotten

The strict version found nothing, but the looser version is the one that carries incident-response weight. A driver that Amcache recorded and the live `drivers` table no longer reports was removed, updated, or never loaded cleanly. It is exactly the residue a BYOVD campaign or a botched cleanup leaves behind.

```sql
SELECT b.path, b.sha1, d.image
FROM amcache_driver_binaries b
LEFT JOIN drivers d ON LOWER(d.image) = b.path
WHERE b.inbox = 0 AND b.kernel_mode = 1 AND d.image IS NULL;
```

```text
| path                                                                                  | sha1                             |
+---------------------------------------------------------------------------------------+----------------------------------+
| c:\program files (x86)\msi\msi center\lib\sys\ntiolib_x64.sys                         | 716c97782fe4ca706df00edb1552e42fd0d8fa49 |
| c:\program files (x86)\msi\msi center\mystic light\lib\ntiolib_x64.sys                | 8dcab06248f8d5565b14ff30abbeadcd07944c2b |
| c:\program files\corsair\corsair device control service\bin\corsairllaccess64.sys     | b7626e7e4281e95153024222503742684b765786 |
| c:\windows\system32\drivers\veracrypt.sys                                             | 0b27ee5e4fc40e76ab159a6f4561b0d2209401a2 |
| c:\windows\system32\driverstore\filerepository\gameflt.inf_amd64_4a86850bc3d081d9\gameflt.sys | 2c2e3c4a4ceee73592335c4df535b9030ce21aff |
| c:\windows\system32\driverstore\filerepository\xvdd.inf_amd64_2050d7d784794b4c\xvdd.sys | 275e0224e51f2aac9529cb12e3814aeb238a2966 |
... 14 more rows (btfilter, mlx4, winverbs, wdboot, ...) ...
20 rows
```

Twenty kernel drivers the live driver list no longer reports. Two of them are worth a second look even on a box you know well. `veracrypt.sys` means someone had an encrypted volume on this machine, and the application is gone while the driver is not. `xvdd.sys` is VirtualBox's shared-graphics driver, same story. The three `ntiolib_x64.sys` copies under MSI Center are the OEM utility residue you expect on a gaming desktop. The point is not that this machine is compromised. The point is that the question *which non-inbox kernel drivers does this machine carry that it no longer reports?* is now an eight-line query you can run mid-incident, on the live host, against the whole fleet.

### Q4: what removable storage has ever been plugged in

Insider-threat and exfiltration investigations open with this question, and it has always required an offline image or a hope that the USB event log was collected.

```sql
SELECT c.friendly_name, c.manufacturer, c.model_name,
       p.device_instance_id, p.first_install_time, p.install_time, c.connected
FROM amcache_device_pnp p
LEFT JOIN amcache_device_containers c ON p.container_id = c.container_id
WHERE UPPER(p.enumerator) = 'USBSTOR'
ORDER BY p.first_install_time DESC;
```

```text
0 rows
```

Provably nothing. No USB mass-storage device has ever been enumerated on this workstation. On a host that has seen one, this returns the device, its friendly name, its first appearance, and its last. The device persists in Amcache after unplugging, so the answer does not depend on when you ask.

### Q5: the machine's own timeline

The same join, without the `USBSTOR` filter, returns every device the machine has ever enumerated: 147 rows.

```text
| friendly_name             | manufacturer                     | model_name       | first_install_time |
+---------------------------+----------------------------------+------------------+--------------------+
| WRK-AI                    | Micro-Star International Co., Ltd. | US Desktop Aegis R | 1733443200 (2024-12-05) |  <- 134 of 147 rows
| (Intel PCIe device)       |                                  |                  | 1757980800 (2025-09-15) |
| (Realtek 2.5G + 10G NICs, audio) |                            |                  | 1761868800 (2025-10-30) |
| (MSI HID peripheral)      |                                  |                  | 1771372800 (2026-02-17) |
| Generic Monitor (S22D390) |                                  | S22D390          | 1781049600 (2026-06-09) |
| (DAF audio endpoint)      |                                  |                  | 1783468800 (2026-07-07) |
```

`first_install_time` is the first time Windows enumerated that specific device. Read across the 147 rows and you have a twenty-month hardware timeline for the box with no event log touched: 134 devices at the 2024-12-05 build, a PCIe add-in in September 2025, NICs and audio in late October 2025, an MSI peripheral in February 2026, a Samsung monitor in June 2026. The machine's birth date comes for free, and a host that claims to be "freshly deployed" while carrying a 2024 device timeline stops being a claim.

One honest decode failure in the table: `driver_ver_time` had 9 non-empty values the extension could not decode, and it reported them as empty with a log line rather than inventing epochs. Same behavior as `link_time` below.

### Q6: filter drivers that do not ship with Windows

A filter driver sits in the I/O path of every request to its device class, which makes it a durable place to hide a keylogger or a storage interceptor. The query resolves each filter to the driver binary Amcache has for it and keeps the ones that are not inbox:

```sql
SELECT p.description, p.class, p.lower_filters, p.upper_filters,
       b.path AS driver_path, b.signed, b.inbox
FROM amcache_device_pnp p
LEFT JOIN amcache_driver_binaries b ON p.sha1 = b.sha1
WHERE (p.lower_filters != '' OR p.upper_filters != '')
  AND (b.inbox = 0 OR b.inbox IS NULL);
```

```text
0 rows
```

Empty surface on this box. Eight lines of SQL, and on a fleet it is the query that turns "do we have a storage filter we cannot account for" from a project into a report.

### Q7: the same devices, resolved to the driver files

The filter query is a join across three tables, so the final demonstration is the same join without the inbox predicate: every PnP device on the machine, resolved to the `.sys` on disk.

```sql
SELECT p.description, p.class, b.path AS driver_path, b.signed, b.inbox
FROM amcache_device_pnp p
LEFT JOIN amcache_driver_binaries b ON p.sha1 = b.sha1;
```

```text
| description              | class     | driver_path                                                                     | signed | inbox |
+--------------------------+-----------+---------------------------------------------------------------------------------+--------+-------+
| ACPI Processor Aggregator| system    | c:\windows\system32\driverstore\filerepository\acpipagr.inf_amd64_... \acpipagr.sys | 1    | 1     |
| Intel(R) Core(TM) i9-14900F | processor | c:\windows\system32\drivers\intelppm.sys                                     | 1      | 1     |
| ACPI Fixed Feature Button| system    | (no driver recorded)                                                            |        |       |
... 144 more rows ...
147 rows
```

Three tables in one query, one hive parse. "What device class, with which filters, backed by which on-disk file, and is that file inbox and signed" used to be four tools and a spreadsheet. It is one question now, and the answer is joinable to anything else in your SQL surface, including the `authenticode` and `hash` tables from Q1.

## What this changes for detection and IR

The seven queries above are the table of contents. The workflows they unlock:

- **Retrospective IOC sweeps.** `sha1 IN (...)` is an index probe per hash against one cached parse of the hive, so a few thousand IOCs is a scheduled query, and the sweep covers what machines have run historically, not just what is running at the moment you ask.
- **Triage without acquisition.** "Is this machine involved?" becomes a query. You reserve imaging for the hosts that come back positive, which is how an incident response keeps its volatile evidence.
- **Hardware and exfiltration history.** Q4 and Q5 answer the two opening questions of an insider investigation, on the live host, with timestamps.
- **Driver provenance.** Q2 through Q3 and Q6 give you the BYOVD question at two strictness levels plus the filter-driver surface, all before the next reboot flushes anything.
- **Correlation in one query.** Because the tables are SQL, Amcache joins to `authenticode`, `hash`, `drivers`, `services` and `programs` in the same statement. "Unsigned, ran from a user directory, no installer behind it, still on disk" is one question instead of four tools.

None of these workflows need the tables to be new to be useful. The data was on the endpoint the whole time. What was missing was a way to ask.

## What to know before you build on it

The caveats are load-bearing, and the extension's own documentation is blunt about them:

- **Saw is not ran.** Amcache records that the appraiser saw a file, which is a good lead and a poor conclusion. Execution claims still need `processes`, `hash`, or your EDR.
- **`last_write_time` is an inventory timestamp.** It is when the appraiser wrote the record, not when the program ran, or when the device attached.
- **Windows 11 splits records in half.** Roughly three in four rows in `amcache_application_files` are hash-only stubs with no path, name, size, or version metadata. Of the rows that carry a path, the majority carry no hash, and fewer than one in ten carry both. Q1's 934 empty-hash rows out of 1,215 are this, live.
- **`link_time` is unreliable by design.** It is the PE header's `TimeDateStamp`, copied without validation. On the measured hosts about seven in ten records decode to something, and the rest are a verbatim copy of the record's product version string or a content hash from a reproducible build. This box reported 1,171 such values in the first parse. Treat a populated value as evidence, an empty one as absence of evidence, never as a zero.
- **`FileId` is a partial hash.** Windows hashes only the first 31,457,280 bytes of a file into it, so a mismatch against a live `hash` read on a larger file is legitimate, and an ordinary update rewrites the file without anything being wrong.
- **Modern hive only.** Windows 10 1809 and later, Windows 11, and Windows Server 2022 and later. An older hive yields zero rows and a log line, not an error.
- **Uninstalls are asymmetric.** Programs disappear from `amcache_applications` while their files remain in `amcache_application_files`. That asymmetry is exactly what makes the Q3-style residue queries work.
- **Privileges.** Reading the hive requires administrator; the raw-volume fallback requires SYSTEM.

## Run it yourself

The extension lives at [github.com/karmine05/amcache](https://github.com/karmine05/amcache) (MIT). The exact invocation from this snapshot:

```powershell
osqueryi --allow_unsafe --extension .\amcache_windows.ext.exe `
  --extensions_require=amcache_windows `
  "SELECT path, sha1, last_write_time FROM amcache_application_files LIMIT 25;"
```

`make windows` builds it, and `make dist` builds amd64 with `SHA256SUMS`. Under fleetd, ship it through TUF rather than hand-editing `extensions.load`, because fleetd rewrites that file wholesale on every config refresh and a hand-appended line dies at the next one:

```sh
fleetctl updates add --name extensions/amcache_windows --platform windows \
  --target ./amcache_windows.ext.exe --version 0.1.0
```

Once the tables are in Fleet, the same seven questions stop being a terminal session and become a hunt an agent can drive, which is where this meets the [vibe hunting work](/dirtyfrag-blog/posts/vibe-hunting-clickfix-fleet-mcp-atc/): fleet-mcp as the tool catalog, ATC as the table constructor, and these seven tables as the Windows half of the surface.

The honest summary, in the spirit of the caveats: Amcache records what the machine has *seen*. It is the most direct map of a host's executable, driver, and device history ever queryable on a live Windows box, and it points you at the right files to image, verify, and explain. It does not, by itself, tell you they ran. That part is still the job.
