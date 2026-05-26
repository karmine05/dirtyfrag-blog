-- ClickFix Fleet/osquery detection bundle — Windows
-- Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/clickfix-copypaste-fleet-detections/
-- All queries validated against https://fleetdm.com/tables/ on 2026-05-26.
-- Platform: Windows. Requires Fleet agent options from clickfix-fleet-agent-options.yml
-- AND Windows Script Block Logging enabled via GPO.

-- =============================================================================
-- Lens 1: Shell obfuscation and stager content
-- =============================================================================

-- 1.1  Encoded / obfuscated PowerShell via script-block logging.
--      cosine_similarity < 0.25 = high obfuscation anomaly score.
SELECT
  datetime(time, 'unixepoch') AS event_time,
  script_path, script_name, script_block_id, script_block_count,
  cosine_similarity, script_text
FROM powershell_events
WHERE
  cosine_similarity < 0.25
  OR script_text LIKE '%FromBase64String%'
  OR script_text LIKE '% -enc %'
  OR script_text LIKE '% -e %'
  OR script_text LIKE '%IEX(%'
  OR script_text LIKE '%Invoke-Expression%'
  OR script_text LIKE '%DownloadString%'
  OR script_text LIKE '%DownloadFile%'
  OR script_text LIKE '%Net.WebClient%';

-- 1.2  PowerShell Operational EventID 4104 cross-reference.
--      Catches script blocks that bypassed osquery's powershell_events for any reason.
SELECT
  datetime(time, 'unixepoch') AS event_time,
  eventid, provider_name, source, data
FROM windows_events
WHERE
  eventid = 4104
  AND provider_name LIKE '%PowerShell%'
  AND (data LIKE '%FromBase64String%'
    OR data LIKE '% -enc %'
    OR data LIKE '%IEX(%'
    OR data LIKE '%DownloadString%');

-- =============================================================================
-- Lens 2: Run dialog / Terminal as process parent
-- =============================================================================

-- 2.1  PowerShell / cmd / wscript / mshta started via ETW.
--      Correlate to explorer.exe Run-dialog parent downstream via (host_id, ppid)
--      against a companion processes query — process_etw_events does not expose
--      parent_name or parent_path.
SELECT datetime, username, path, cmdline, ppid, pid, type
FROM process_etw_events
WHERE
  type = 'ProcessStart'
  AND (path LIKE '%\powershell.exe'
    OR path LIKE '%\cmd.exe'
    OR path LIKE '%\wscript.exe'
    OR path LIKE '%\mshta.exe');

-- =============================================================================
-- Lens 3: Persistence and staging artefacts
-- =============================================================================

-- 3.1  NetSupport RAT installation footprint.
--      Fleet policy candidate (fail-on-any-row) on hosts where NetSupport is
--      not approved IT tooling.
SELECT name, version, install_date, publisher, uninstall_string
FROM programs
WHERE
  name LIKE '%NetSupport%'
  OR publisher LIKE '%NetSupport%';

-- 3.2  Random folder in %LOCALAPPDATA% containing client32.exe (NetSupport).
--      file_events is macOS+Linux only — use file+hash snapshot on Windows.
SELECT f.path, f.filename, f.size, f.mtime, h.sha256
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE f.path LIKE 'C:\Users\%\AppData\Local\%\client32.exe';

-- 3.6  Classic Run-key persistence in registry.
--      Filter result set downstream by data LIKE '%AppData\Local\%' or by
--      non-Microsoft publisher to suppress benign entries.
SELECT path, name, data, mtime
FROM registry
WHERE
  path LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run\%'
  OR path LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\%'
  OR path LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\%';
