-- queries/03-userspace-consumers.sql
--
-- Find userspace processes likely to be pinning esp4/esp6 or rxrpc.
--
-- Covers two classes of consumer:
--   1. Traditional IPsec daemons (charon, pluto, etc.) — these manage
--      xfrm state via their own daemons and pin xfrm_user that way.
--   2. Container runtimes and orchestrators (dockerd, containerd) —
--      Docker Swarm encrypted overlay networks program xfrm directly via
--      netlink, with no userland IPsec daemon in the picture. This is the
--      non-obvious case that a generic "find IPsec consumers" query
--      would miss.
--
-- Run after 02-module-state.sql identifies a stuck module. The process
-- list returned here is the candidate set for what to stop (or carve out
-- of the modprobe-blacklist mitigation).

SELECT
  p.pid,
  p.name        AS process,
  p.path,
  p.cmdline,
  p.start_time,
  u.username
FROM processes p
LEFT JOIN users u ON p.uid = u.uid
WHERE
  -- Traditional IPsec stack
  p.name IN ('charon','pluto','starter','ipsec','iked','racoon','swanctl')
  OR p.cmdline LIKE '%strongswan%'
  OR p.cmdline LIKE '%libreswan%'
  OR p.cmdline LIKE '%/ipsec%'
  OR p.path  LIKE '%/charon%'
  OR p.path  LIKE '%/pluto%'

  -- Container runtimes (Docker Swarm encrypted overlay → xfrm via netlink)
  OR p.name IN ('dockerd','containerd','docker-proxy')
  OR p.path LIKE '%/dockerd%'
  OR p.path LIKE '%/containerd%';
