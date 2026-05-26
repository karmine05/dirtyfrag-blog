-- SHADOW-EARTH-053 Fleet/osquery detection bundle — Windows
-- Source: https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html (Lunghi & Silva, 30 Apr 2026)
-- Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/shadow-earth-053-fleet-detections/
-- All queries validated against https://fleetdm.com/tables/ on 2026-05-26.
-- Platform: Windows. Requires Fleet agent options listed in se053-fleet-agent-options.yml.

-- =============================================================================
-- Lens 1: Web shell + Exchange/IIS abuse
-- =============================================================================

-- 1.1  Retro-hunt: GODZILLA web shell filenames in Exchange/IIS web roots.
--      Fleet policy candidate (fail-on-any-row).
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE (f.directory = 'C:\inetpub\wwwroot\aspnet_client\system_web'
    OR f.directory = 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth')
  AND f.filename IN ('error.aspx','errorFE.aspx','signout.aspx','warn.aspx','data.aspx',
                     'page.aspx','TimeinLogout.aspx','timeout.aspx','charcode.aspx',
                     'tunnel.ashx','i.aspx','2.aspx');

-- 1.3  IIS worker spawning LOLBINs (ETW). Correlate to w3wp.exe parent downstream
--      (process_etw_events does not expose parent_name; only ppid).
SELECT datetime, username, path, cmdline, ppid, pid, type
FROM process_etw_events
WHERE type = 'ProcessStart'
  AND (path LIKE '%\cmd.exe'
    OR path LIKE '%\powershell.exe'
    OR path LIKE '%\whoami.exe'
    OR path LIKE '%\net.exe'
    OR path LIKE '%\rar.exe'
    OR path LIKE '%\rundll32.exe');

-- =============================================================================
-- Lens 2: ShadowPad persistence + layered tunnels
-- =============================================================================

-- 2.1  ShadowPad loader DLLs and binaries on disk in publicly-writable dirs.
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE (f.path LIKE 'C:\Users\Public\%' OR f.path LIKE 'C:\ProgramData\%')
  AND (f.filename IN ('CIATosBtKbd.exe','TosBtKbd.dll','graphics-hook-filter32.dll',
                      'imjp14k.dll','Uxtheme.dll','MPS.dll')
       OR f.filename LIKE 'mdync.exe');

-- 2.2  ShadowPad shellcode in registry. Fleet policy candidate (fail-on-any-row).
SELECT path, key, name, type, mtime
FROM registry
WHERE path LIKE 'HKEY_USERS\%\Software\%\scode';

-- 2.3  Scheduled Task M1onltor + tasks running from publicly-writable dirs.
SELECT name, action, enabled, state, last_run_time, next_run_time, path
FROM scheduled_tasks
WHERE name = 'M1onltor'
   OR path LIKE 'C:\Users\Public\%'
   OR path LIKE 'C:\ProgramData\%';

-- 2.4  LocalAccountTokenFilterPolicy flipped to 1 — generic UAC bypass.
--      Context-builder, not a standalone IOC.
SELECT path, name, data, mtime
FROM registry
WHERE path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  AND name = 'LocalAccountTokenFilterPolicy'
  AND data = '1';

-- 2.5  Tunnel binaries by process name and cmdline.
--      'code.exe' and 'wt.exe' deliberately excluded from name-filter (VS Code / Windows Terminal).
SELECT pid, name, path, cmdline, parent
FROM processes
WHERE name IN ('iox.exe','gost.exe')
   OR cmdline LIKE '%--listen socks%'
   OR cmdline LIKE '%client.toml%'
   OR cmdline LIKE '%wstunnel%';

-- 2.6a AnyDesk installation inventory. Actionable on hosts where AnyDesk should not exist
--      (Exchange servers, DCs).
SELECT name, version, install_location, publisher
FROM programs
WHERE name LIKE '%AnyDesk%';

-- =============================================================================
-- Lens 3: Credential theft + mailbox export
-- =============================================================================

-- 3.1  rundll32 with Mimikatz / DCSync signatures via Sysmon -> windows_events.
--      Requires Sysmon installed on host and Windows Event Log subscriber enabled.
SELECT datetime, data
FROM windows_events
WHERE source = 'Microsoft-Windows-Sysmon'
  AND eventid = 1
  AND data LIKE '%rundll32.exe%'
  AND (data LIKE '%sekurlsa::logonpasswords%'
    OR data LIKE '%lsadump::sam%'
    OR data LIKE '%lsadump::dcsync%'
    OR data LIKE '%newdcsync%');

-- 3.2  Exchange PowerShell enumeration + ExchangeExport via EWS.
--      Requires Script Block Logging enabled via GPO + powershell_events_subscriber.
SELECT datetime, script_name, script_path, script_text, cosine_similarity
FROM powershell_events
WHERE script_text LIKE '%Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn%'
   OR script_text LIKE '%Get-Mailbox%'
   OR script_text LIKE '%Get-User%'
   OR script_text LIKE '%New-MailboxExportRequest%'
   OR script_text LIKE '%ExchangeExport%'
   OR script_text LIKE '%userAccountControl%';

-- 3.3  PST snapshot under Windows Temp — exfil-prep signal.
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE f.directory = 'C:\Windows\Temp'
  AND f.filename LIKE '%.pst';
