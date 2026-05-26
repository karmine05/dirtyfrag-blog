-- SHADOW-EARTH-053 Fleet/osquery detection bundle — Linux
-- Source: https://www.trendmicro.com/en_us/research/26/d/inside-shadow-earth-053.html (Lunghi & Silva, 30 Apr 2026)
-- Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/shadow-earth-053-fleet-detections/
-- Platform: Linux. Requires Fleet agent options listed in se053-fleet-agent-options.yml.
-- NOTE: NOODLERAT attribution to SHADOW-EARTH-053 is LOW confidence per Trend Micro.

-- =============================================================================
-- Lens 1: Web shell + IIS-on-Linux equivalents
-- =============================================================================

-- 1.2  FIM: new server-side script files in web roots.
--      Pre-requisite: file_paths category 'linux_webroot' configured in agent options.
SELECT time, action, target_path, category
FROM file_events
WHERE category = 'linux_webroot'
  AND (target_path LIKE '%.php'
    OR target_path LIKE '%.jsp'
    OR target_path LIKE '%.py'
    OR target_path LIKE '%.cgi'
    OR target_path LIKE '%.sh');

-- =============================================================================
-- Lens 2: Connections to published C2 + AnyDesk network activity
-- =============================================================================

-- 2.6b AnyDesk outbound connections (Linux). Tighten by Fleet host label.
SELECT s.time, s.action, s.remote_address, s.remote_port,
       p.pid, p.name, p.path, p.cmdline
FROM socket_events s
JOIN processes p USING (pid)
WHERE p.name LIKE 'anydesk%'
  AND s.action = 'connect'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT REGEXP '^172\.(1[6-9]|2[0-9]|3[01])\.'
  AND s.remote_address NOT LIKE '127.%';

-- 2.7  Connections to Trend-published SHADOW-EARTH-053 C2 infrastructure.
--      Atomic IOCs — will rotate within weeks of publication.
SELECT s.time, s.action, s.remote_address, s.remote_port, p.pid, p.name, p.path
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.action = 'connect'
  AND (s.remote_address IN ('141.164.46.77','96.9.125.227','194.38.11.3')
       OR s.remote_port IN (8067, 1790));

-- =============================================================================
-- Lens 3: Linux NOODLERAT staging + web-tier unexpected outbound
-- =============================================================================

-- 3.5  Web-tier hosts shouldn't make outbound from non-web-server processes.
--      Allowlist captures legitimate exceptions; tune for your environment.
SELECT s.time, s.remote_address, s.remote_port, p.pid, p.name, p.path, p.cmdline
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.action = 'connect'
  AND (
    (s.remote_address = '194.38.11.3' AND s.remote_port = 1790)
    OR s.remote_port IN (1790, 8080, 8443)
  )
  AND p.name NOT IN ('nginx','httpd','apache2','envoy','haproxy','traefik');

-- 3.6  DNS resolution of NOODLERAT C2 domain (requires dns_resolvers / dns_lookup_events).
--      Add as a scheduled query if you have a DNS-event source wired in.
SELECT s.time, s.remote_address, s.remote_port, p.pid, p.name, p.cmdline
FROM socket_events s
JOIN processes p USING (pid)
WHERE s.remote_port = 53
  AND s.action = 'connect'
  AND p.cmdline LIKE '%office365-update.com%';
