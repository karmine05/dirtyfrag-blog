-- eMudhra / emSign CA compromise (Oct 2026): Fleet policies. Each passes (returns 1) when the host is clean.
-- Attach the matching emudhra-remediate-* script as the policy's "Run script" automation.

-- macOS: Apple CLI bundle and fleetd bundle trust neither compromised root.
SELECT 1 FROM os_version WHERE NOT EXISTS (
  SELECT 1 FROM certificates
  WHERE path IN ('/etc/ssl/cert.pem', '/opt/orbit/certs.pem')
    AND sha1 IN ('3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1', 'd1eb23a46d17d68fd92564c2f1f1601764d8e349'));

-- Linux: system CA bundle and fleetd bundle trust neither compromised root.
SELECT 1 FROM os_version WHERE NOT EXISTS (
  SELECT 1 FROM certificates
  WHERE sha1 IN ('3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1', 'd1eb23a46d17d68fd92564c2f1f1601764d8e349'))
AND NOT EXISTS (
  SELECT 1 FROM certificates
  WHERE path = '/opt/orbit/certs.pem'
    AND sha1 IN ('3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1', 'd1eb23a46d17d68fd92564c2f1f1601764d8e349'));

-- Windows: fleetd bundle no longer trusts either compromised root (osqueryd TLS to Fleet).
SELECT 1 FROM os_version WHERE NOT EXISTS (
  SELECT 1 FROM file f JOIN file_lines l ON l.path = f.path
  WHERE f.path = 'C:\Program Files\Orbit\certs.pem'
    AND l.line IN ('CBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7',
                   '8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C'));
