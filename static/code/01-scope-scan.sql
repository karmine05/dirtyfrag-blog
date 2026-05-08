-- queries/01-scope-scan.sql
--
-- Initial Dirty Frag scope scan. Returns one row per host with the artifacts
-- needed to assess exposure: distro, kernel, uptime, and presence of each
-- implicated module.
--
-- This query does NOT depend on a CVE being assigned. It reads only what
-- osquery can see directly: distro metadata, kernel version, kernel module
-- state, and uptime.
--
-- Run as a live query targeted at all Linux hosts. Pair with the per-team
-- breakdown in Fleet's UI to understand spread.

SELECT
  os.platform,
  os.name              AS distro_name,
  os.version           AS distro_version,
  os.codename          AS distro_codename,
  k.version            AS kernel_version,
  k.arch,
  CAST(u.total_seconds / 86400 AS INTEGER) AS uptime_days,

  -- Per-module presence flags (1 = currently loaded, 0 = not loaded).
  -- Note: absence here is NOT a mitigation — these modules auto-load on
  -- demand when an unprivileged process opens the relevant socket family.
  -- The presence/absence pattern only tells you what's loaded RIGHT NOW.
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'esp4'),       0) AS mod_esp4,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'esp6'),       0) AS mod_esp6,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'rxrpc'),      0) AS mod_rxrpc,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'af_rxrpc'),   0) AS mod_af_rxrpc,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'xfrm_user'),  0) AS mod_xfrm_user,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'xfrm_algo'),  0) AS mod_xfrm_algo,
  COALESCE((SELECT 1 FROM kernel_modules WHERE name = 'algif_aead'), 0) AS mod_algif_aead,

  -- Mitigation state hints
  COALESCE((SELECT 1 FROM file WHERE path = '/etc/modprobe.d/dirtyfrag.conf' AND size > 0), 0) AS modprobe_blacklist_deployed,
  COALESCE((SELECT 1 FROM file WHERE path = '/etc/sysctl.d/99-dirtyfrag-userns.conf' AND size > 0), 0) AS userns_mitigation_deployed
FROM os_version os
CROSS JOIN kernel_info k
CROSS JOIN uptime u;
