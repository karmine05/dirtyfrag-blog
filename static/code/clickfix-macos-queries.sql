-- ClickFix Fleet/osquery detection bundle — macOS
-- Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/clickfix-copypaste-fleet-detections/
-- All queries validated against https://fleetdm.com/tables/ on 2026-05-26.
-- Platform: darwin. Requires Fleet agent options from clickfix-fleet-agent-options.yml
-- AND EndpointSecurity entitlement granted via MDM for es_process_events.

-- =============================================================================
-- Lens 1: Shell obfuscation and stager content
-- =============================================================================

-- 1.3  Suspicious shell stagers: zsh / bash / sh with piped curl or base64.
--      Time window 24h; tighten or widen per environment.
SELECT
  datetime(time, 'unixepoch') AS event_time,
  path, cmdline, parent, uid
FROM process_events
WHERE
  path IN ('/bin/zsh','/bin/bash','/bin/sh')
  AND (
    (cmdline LIKE '%curl %' AND cmdline LIKE '%|%')
    OR cmdline LIKE '%base64%-d%|%'
    OR cmdline LIKE '%base64 --decode%|%'
    OR cmdline LIKE '% | sh%'
    OR cmdline LIKE '% | zsh%'
    OR cmdline LIKE '% | bash%'
  )
  AND time > strftime('%s','now') - 86400;

-- 1.4  Terminal-sourced activity via macOS Unified Log.
--      Corroborates that the shell command originated from Terminal.app.
SELECT
  datetime(timestamp, 'unixepoch') AS log_time,
  process, subsystem, category, message
FROM unified_log
WHERE
  process = 'Terminal'
  AND (message LIKE '%curl %' OR message LIKE '%base64%' OR message LIKE '%wget %');

-- =============================================================================
-- Lens 2: Terminal as process parent (EndpointSecurity)
-- =============================================================================

-- 2.2  Shells with piped curl via EndpointSecurity (richer than audit-framework
--      process_events: includes signing_id, team_id, platform_binary).
SELECT
  datetime, pid, parent_pid, path, cmdline, signing_id, team_id, platform_binary
FROM es_process_events
WHERE
  path IN ('/bin/zsh','/bin/bash','/bin/sh')
  AND cmdline LIKE '%curl %'
  AND cmdline LIKE '%|%';

-- =============================================================================
-- Lens 3: Persistence and staging artefacts
-- =============================================================================

-- 3.3  AppleScript stealer staging directory snapshot.
--      Any contents are actionable — particularly login.keychain-db copies + .zip
--      archives in /tmp/.xdivcmp/.
--      file table accepts path LIKE when pattern starts with a literal prefix.
SELECT path, uid, gid, mode, size, mtime
FROM file
WHERE path LIKE '/tmp/.xdivcmp/%';

-- 3.4  Evented monitor for new artefacts in the staging directory.
--      Requires /tmp/.xdivcmp/ declared under file_paths in agent options.
SELECT
  datetime(time, 'unixepoch') AS event_time,
  action, target_path, sha256, size
FROM file_events
WHERE target_path LIKE '/tmp/.xdivcmp/%';

-- 3.5  LaunchDaemons referencing user-home scripts with persistence flags.
--      file_contents requires path equality, not LIKE. CTE pattern:
--      enumerate plists via file (which accepts LIKE), then join into
--      file_contents row-by-row. Fleet's planner unrolls the join into
--      per-path equality lookups.
WITH suspect_plists AS (
  SELECT path FROM file
  WHERE path LIKE '/Library/LaunchDaemons/%.plist'
)
SELECT fc.path, fc.contents
FROM suspect_plists sp
JOIN file_contents fc ON fc.path = sp.path
WHERE
  fc.contents LIKE '%/Users/%'
  AND (fc.contents LIKE '%RunAtLoad%' OR fc.contents LIKE '%KeepAlive%')
  AND (fc.contents LIKE '%/bin/bash%' OR fc.contents LIKE '%/bin/zsh%');
