-- SHADOW-EARTH-053 Fleet/osquery detection bundle — macOS
-- Source: https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html (Lunghi & Silva, 30 Apr 2026)
-- Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/shadow-earth-053-fleet-detections/
-- Platform: darwin. macOS coverage is precautionary — Trend Micro did not observe
-- macOS targeting, but operators with executive-mailbox access frequently pivot to
-- the admin's laptop with Exchange admin session still warm.

-- =============================================================================
-- Lens 2: Tunnels + AnyDesk on macOS
-- =============================================================================

-- 2.6c AnyDesk outbound connections (macOS). Restrict by Fleet host label.
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

-- 2.7  Connections to Trend-published SHADOW-EARTH-053 infrastructure (macOS).
SELECT s.time, s.action, s.remote_address, s.remote_port, p.pid, p.name, p.path
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.action = 'connect'
  AND (s.remote_address IN ('141.164.46.77','96.9.125.227','194.38.11.3')
       OR s.remote_port IN (8067, 1790));

-- =============================================================================
-- Lens 3: Persistence — macOS LaunchAgent equivalents of M1onltor
-- =============================================================================

-- 3.4  Suspicious user-level LaunchAgents in unusual paths.
--      run_at_load and keep_alive are text columns; values aren't normalised.
SELECT label, path, program, program_arguments, run_at_load, keep_alive, username
FROM launchd
WHERE (run_at_load = '1' OR run_at_load = 'true')
  AND (keep_alive   = '1' OR keep_alive   = 'true')
  AND (program LIKE '/Users/%/Downloads/%'
    OR program LIKE '/Users/%/Library/%/tmp/%'
    OR program LIKE '/tmp/%'
    OR program LIKE '/private/tmp/%');

-- 3.7  EndpointSecurity-backed process creation events — pivot point for
--      Office or browser spawning curl / bash / osascript after inbound connections.
--      Schema notes:
--        - time column is 'time' (bigint epoch), NOT 'datetime'
--        - parent-process column is 'parent' (bigint), NOT 'parent_pid'
SELECT datetime(time, 'unixepoch') AS event_time,
       parent, pid, path, cmdline, signing_id, team_id, platform_binary
FROM es_process_events
WHERE path LIKE '/usr/bin/curl'
   OR path LIKE '/bin/bash'
   OR path LIKE '/bin/sh'
   OR path LIKE '/usr/bin/osascript';
