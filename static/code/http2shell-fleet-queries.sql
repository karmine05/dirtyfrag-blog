-- HTTP2Shell / CVE-2026-111497 (Brotli decoder 1.0.3-1.2.0) hunting queries for Fleet.
-- https://karmine05.github.io/dirtyfrag-blog/posts/http2shell-brotli-fleet/
-- Scope each query to the platform label named in its header.
--
-- Version logic: SQLite string comparison is lexical ('1.0.9' < '1.0.10' is false,
-- '24.9.0' > '24.22.1' is true), so these queries never use < or > on version
-- strings. Brotli uses an exact list of the nine vulnerable releases. Node.js
-- and Bun split major.minor.patch with CAST (which takes the leading digits,
-- so '22.1-1nodesource1' casts to 22) and compare a numeric key.
--
-- Fixed versions (Tanium, nodejs.org, PyPI, GitHub releases, verified 2026-10-26):
--   brotli      1.0.10, 1.1.1, 1.2.1
--   Node.js     22.23.4, 24.22.1, 26.12.1 (20.x, 23.x, 25.x are EOL, no fix)
--   Bun         1.4.4 (vulnerable 1.0.21-1.4.3)
--   PyPI        Brotli 1.2.1, brotlicffi 1.2.1.0
-- Distros backport without bumping the upstream number (Debian 12 fixed in
-- brotli 1.0.9-2+deb12u1), so distro brotli packages are reported as REVIEW,
-- not auto-classified.

-- ---------------------------------------------------------------------------
-- 1. Linux: brotli and nodejs packages (deb + rpm)
-- ---------------------------------------------------------------------------
WITH pk AS (
  SELECT name, version, 'deb' AS src FROM deb_packages
  WHERE name LIKE '%brotli%' OR name = 'nodejs'
  UNION ALL
  SELECT name, version || '-' || release, 'rpm' FROM rpm_packages
  WHERE name LIKE '%brotli%' OR name = 'nodejs'
),
k AS (
  SELECT *, CAST(version AS INT) AS maj,
    CAST(substr(version, instr(version,'.')+1) AS INT) AS mnr,
    CAST(substr(substr(version, instr(version,'.')+1), instr(substr(version, instr(version,'.')+1),'.')+1) AS INT) AS pat
  FROM pk
)
SELECT name, version, src,
  CASE WHEN name <> 'nodejs' THEN 'REVIEW-vs-advisory'
       WHEN (maj=22 AND mnr*1000+pat>=23004) OR (maj=24 AND mnr*1000+pat>=22001)
         OR (maj=26 AND mnr*1000+pat>=12001) OR maj>26 THEN 'FIXED'
       ELSE 'VULNERABLE' END AS status
FROM k;

-- ---------------------------------------------------------------------------
-- 2. macOS: Homebrew (brotli, node, bun, envoy) and Node.js .pkg receipts
-- ---------------------------------------------------------------------------
WITH src AS (
  SELECT name, version, path AS location FROM homebrew_packages
  WHERE name = 'brotli' OR name LIKE 'node%' OR name IN ('bun','envoy')
  UNION ALL
  SELECT package_id, version, location FROM package_receipts
  WHERE package_id LIKE 'org.nodejs.node%'
),
k AS (
  SELECT *, ltrim(version,'v') AS v FROM src
),
n AS (
  SELECT name, version, location, CAST(v AS INT) AS maj,
    CAST(substr(v, instr(v,'.')+1) AS INT) AS mnr,
    CAST(substr(substr(v, instr(v,'.')+1), instr(substr(v, instr(v,'.')+1),'.')+1) AS INT) AS pat
  FROM k
)
SELECT name, version, location,
  CASE WHEN name = 'brotli' AND version IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
       WHEN name = 'brotli' THEN 'FIXED'
       WHEN name = 'bun' AND maj*1000000+mnr*1000+pat BETWEEN 1000021 AND 1004003 THEN 'VULNERABLE'
       WHEN name = 'bun' THEN 'FIXED'
       WHEN name = 'envoy' THEN 'REVIEW'
       WHEN (maj=22 AND mnr*1000+pat>=23004) OR (maj=24 AND mnr*1000+pat>=22001)
         OR (maj=26 AND mnr*1000+pat>=12001) OR maj>26 THEN 'FIXED'
       ELSE 'VULNERABLE' END AS status
FROM n;

-- ---------------------------------------------------------------------------
-- 3. All platforms: Python Brotli / brotlicffi / brotlipy, per user
-- ---------------------------------------------------------------------------
SELECT u.username, p.name, p.version, p.path,
  CASE
    WHEN lower(p.name) = 'brotli' AND p.version IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
    WHEN lower(p.name) = 'brotlicffi' AND substr(p.version,1,5) IN ('1.0.3','1.0.4','1.0.5','1.0.6','1.0.7','1.0.8','1.0.9','1.1.0','1.2.0') THEN 'VULNERABLE'
    WHEN lower(p.name) = 'brotlipy' THEN 'REVIEW'
    ELSE 'FIXED' END AS status
FROM users u CROSS JOIN python_packages p USING (uid)
WHERE lower(p.name) IN ('brotli','brotlicffi','brotlipy');

-- ---------------------------------------------------------------------------
-- 4. macOS/Linux: Node and Bun binaries outside package managers
--    (nvm, Volta, fnm, manual installs). Version is in path or symlink target.
-- ---------------------------------------------------------------------------
SELECT path, symlink_target_path, size, datetime(mtime,'unixepoch') AS modified FROM file
WHERE path IN ('/usr/bin/node','/usr/local/bin/node','/opt/homebrew/bin/node','/usr/local/bin/bun','/home/linuxbrew/.linuxbrew/bin/node')
   OR path LIKE '/Users/%/.nvm/versions/node/%/bin/node'
   OR path LIKE '/home/%/.nvm/versions/node/%/bin/node'
   OR path LIKE '/Users/%/.volta/tools/image/node/%/bin/node'
   OR path LIKE '/home/%/.volta/tools/image/node/%/bin/node'
   OR path LIKE '/Users/%/Library/Application Support/fnm/node-versions/%/installation/bin/node'
   OR path LIKE '/home/%/.local/share/fnm/node-versions/%/installation/bin/node'
   OR path LIKE '/Users/%/.bun/bin/bun'
   OR path LIKE '/home/%/.bun/bin/bun';

-- ---------------------------------------------------------------------------
-- 5. Windows: Node.js / Bun installs, node.exe and .NET native DLL versions
--    (.NET has no vendor fix yet; inventory only)
-- ---------------------------------------------------------------------------
SELECT 'program' AS src, name, version, install_location AS path FROM programs
WHERE name LIKE 'Node.js%' OR name LIKE '%Bun%'
UNION ALL
SELECT 'file', filename, product_version, path FROM file
WHERE path = 'C:\Program Files\nodejs\node.exe'
   OR path LIKE 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App\%\System.IO.Compression.Native.dll'
   OR path LIKE 'C:\Users\%\.bun\bin\bun.exe'
   OR path LIKE 'C:\Users\%\AppData\Roaming\nvm\%\node.exe';

-- ---------------------------------------------------------------------------
-- 6. All platforms: network-reachable processes that are a known runtime or
--    have a brotli shared library mapped. process_memory_map is only read for
--    listening pids. Static/bundled decoders (Node, Bun) never show a library;
--    that is what queries 1-5 are for.
-- ---------------------------------------------------------------------------
WITH lp AS (
  SELECT DISTINCT pid, port, address FROM listening_ports
  WHERE address NOT IN ('127.0.0.1','127.0.1.1','::1','') AND port > 0
)
SELECT DISTINCT p.pid, p.name, p.path, lp.port, lp.address,
  (SELECT path FROM process_memory_map m WHERE m.pid = p.pid AND m.path LIKE '%brotli%' LIMIT 1) AS brotli_lib
FROM lp JOIN processes p USING (pid)
WHERE lower(p.name) IN ('node','node.exe','bun','bun.exe','envoy','envoy.exe','dotnet','dotnet.exe','nginx','java')
   OR brotli_lib IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 7. Policy pattern (one per platform): passes when no VULNERABLE row exists.
--    Paste query 1, 2 or 3 in place of <status query>.
-- ---------------------------------------------------------------------------
-- SELECT 1 FROM os_version WHERE NOT EXISTS (
--   SELECT 1 FROM ( <status query> ) WHERE status = 'VULNERABLE'
-- );
