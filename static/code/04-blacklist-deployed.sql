-- queries/04-blacklist-deployed.sql
--
-- Verification: confirms that /etc/modprobe.d/dirtyfrag.conf is in place
-- and well-formed on the host. Used as the SQL backing the
-- "dirtyfrag-blacklist-deployed" Fleet policy.
--
-- Returns a row when the blacklist is deployed and matches expected
-- properties; returns nothing when the file is missing, empty, or has
-- wrong permissions.

SELECT
  path,
  size,
  mode,
  mtime,
  uid,
  gid
FROM file
WHERE path = '/etc/modprobe.d/dirtyfrag.conf'
  AND size > 0
  AND mode = '0644'
  AND uid  = 0;
