-- queries/02-module-state.sql
--
-- Diagnostic: post-mitigation kernel module state. Use after running the
-- mitigation script to identify hosts where a target module is still
-- resident in the running kernel.
--
-- Read the result as follows:
--   * status = "Live" with non-empty `used_by` listing dependent modules
--     → kernel-side hold (another loaded module depends on this one).
--   * status = "Live" with `used_by = '-'` (or empty) but the module is
--     present → userspace pin (something is using the netlink interface
--     or the module's character device). Pair with 03-userspace-consumers.sql
--     to identify the holder.
--
-- Pass this against hosts flagged by 04-blacklist-deployed.sql as
-- "blacklist deployed" but still showing target modules in 01-scope-scan.sql.

SELECT
  name,
  size,
  used_by,
  status,
  address
FROM kernel_modules
WHERE name IN (
  'esp4',
  'esp6',
  'rxrpc',
  'af_rxrpc',
  'xfrm_user',
  'xfrm_algo',
  'xfrm4_tunnel',
  'xfrm6_tunnel',
  'algif_aead'
);
