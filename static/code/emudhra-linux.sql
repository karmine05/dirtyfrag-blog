-- eMudhra / emSign intermediate CA compromise (Oct 2026) - Linux exposure + mitigation status.
-- One row per finding: finding | item | detail | status
-- certificates table reads /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt, /var/lib/ca-certificates/ca-bundle.pem
SELECT 'root_in_ca_bundle' AS finding, common_name AS item, path AS detail,
       CASE sha1
         WHEN '3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1' THEN 'UNPATCHED emSign ECC Root CA - G3 still trusted (fixed ca-certificates removes it)'
         WHEN 'd1eb23a46d17d68fd92564c2f1f1601764d8e349' THEN 'AAA Certificate Services trusted: Sectigo cross-sign path open (Mozilla-derived bundles no longer ship it; old bundle or manually added)'
         ELSE 'emSign Root TLS/CS CA - G3 present (not in Mozilla bundle; manually added)'
       END AS status
FROM certificates
WHERE sha1 IN ('3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1',
               'd1eb23a46d17d68fd92564c2f1f1601764d8e349',
               '39d3236e4a609ab6190cbfa1ad02b3cc61dfc2c3',
               '1f74b6010a219fd9ca058d07aa053d15efd9300d')
UNION ALL
SELECT 'compromised_intermediate_present', common_name, path || ' sha1=' || sha1, 'IOC_HIT investigate'
FROM certificates
WHERE subject_key_id IN ('e21e2fe71c19390e554b62c120245735248a2514',  -- EM DV TLS CA - G3B
                         '9bd86551afe7e72c37ad08ee6919d9bf3784ae0a',  -- EM OV TLS CA - G3B
                         '3edc20d9894698877b873fd88147b25c15d84706',  -- EM EV TLS CA - G3B
                         'ae7e105c3c2996c1a847270559f1e03dd4e50af3',  -- EM DV TLS CA - G3C
                         '34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c',  -- EM OV TLS CA - G3C
                         'a6255e80a94db7f3967c1bc791df92bcee4beb5f',  -- EM EV TLS CA - G3C
                         '79fae8eccfdb0d758da458d69fb6eddc7c49dee6',  -- EM OV CS CA - G3B
                         'ee6f73298d6fbfa7b31bc39534f61556447866b7') -- EM OV CS CA - G3C
   OR sha1 IN ('a99b289464f3b44343270a7a1e910f02370483fe','1396be1372bc93dfa2a433ca964dba91548a6e57',
               '5f014e0db3bb8f950e0598ab280846d383fc57be','5dfa19197d1c1cf629af7c0cd865543c5050227c',
               'f33acd1f5d31aa81ac18c72c928446226d3d5914','19069bd6533bff93fb67c71fb3376b4ea7402c3b',
               '8ad23bc78845d6faae1d534bac89f0e36ba55a11','4b0944c14f8c2ccba4e4f32104ad920fa15ee331',
               '7fcc31aab874ce6c8ee8584f54cfd08646b54117','305fc1e253dcab71b95d4995dae3cb09d562f22a',
               'c988f3d0cc1629ffc43165d6464c9b6ef73d6e48','8588708e875a1f8aa83524f3559080f7e17068c7',
               'd33195a244046a3263fb5e0e83c6803a5b2e7bc3','ee26d7ae3cc71718f6e07d7d0095076f0c158f63',
               '1f4a5d178f8b6a8ef0f6784155bd5fea91158b12','7fde64753a957b98f172fd2ab0d922551909c7ba')
UNION ALL
-- Fixed: Ubuntu 20260816ubuntu0.{22.04,24.04,26.04,26.10}.1, Debian 20250419~deb12u2 / 20250419+deb13u1, Fedora 2026.2.92_v9.0.319, Alpine 20261020-r0
SELECT 'ca_certificates_pkg', name, version || ' status=' || status, 'COMPARE to fixed version for this distro'
FROM deb_packages
WHERE name = 'ca-certificates'
UNION ALL
SELECT 'ca_certificates_pkg', name, version || '-' || release, 'COMPARE to fixed version for this distro'
FROM rpm_packages
WHERE name = 'ca-certificates'
UNION ALL
SELECT 'python_certifi', name || ' uid=' || uid, version || ' ' || path,
       -- Distro-packaged certifi points at the system bundle (Debian/Ubuntu dist-packages, Fedora/RHEL site-packages).
       CASE WHEN path LIKE '/usr/lib/python3/dist-packages%'
              OR path LIKE '/usr/lib/python3%/site-packages%'
              OR path LIKE '/usr/lib64/python3%/site-packages%'
            THEN 'OK_DISTRO_CERTIFI (patched to use system bundle; see ca_certificates_pkg)'
            WHEN CAST(substr(version, 1, 4) AS INTEGER) * 10000
               + CAST(substr(version, 6, instr(substr(version, 6), '.') - 1) AS INTEGER) * 100
               + CAST(substr(version, 6 + instr(substr(version, 6), '.')) AS INTEGER) >= 20261019
            THEN 'FIXED' ELSE 'UPDATE certifi>=2026.10.19' END
FROM python_packages
WHERE name = 'certifi'
UNION ALL
SELECT 'toolchain', name, version, 'REVIEW Go>=1.27.3/1.26.10, Node>=22.23.4/24.22.1/26.12.1 (binaries built earlier stay vulnerable)'
FROM deb_packages
WHERE name IN ('golang-go', 'nodejs')
UNION ALL
SELECT 'toolchain', name, version || '-' || release, 'REVIEW Go>=1.27.3/1.26.10, Node>=22.23.4/24.22.1/26.12.1'
FROM rpm_packages
WHERE name IN ('golang', 'nodejs')
UNION ALL
-- fleetd ships its own CA bundle. osqueryd uses it (not the OS trust store) for TLS to Fleet.
-- It is written at install time and never refreshed, so the OS vendor block does not cover it.
SELECT 'fleetd_osquery_ca_bundle', common_name, path,
       'EXPOSED osqueryd-to-Fleet TLS trusts this root; run the remediation script'
FROM certificates
WHERE path = '/opt/orbit/certs.pem'
  AND sha1 IN ('3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1', 'd1eb23a46d17d68fd92564c2f1f1601764d8e349')
UNION ALL
SELECT 'fleetd_agent', 'orbit ' || version, 'channel=' || orbit_channel || ' scripts_enabled=' || scripts_enabled,
       'INFO orbit is Go; on Linux it reads the system bundle, so it is safe only once root_in_ca_bundle rows are gone'
FROM orbit_info
UNION ALL
-- Go tools installed with go install (each user's ~/go/bin).
SELECT 'go_binary', name || ' ' || version, installed_path || ' ' || go_version,
       CASE WHEN CAST(substr(go_version, 5) AS INTEGER) >= 28
              OR (CAST(substr(go_version, 5) AS INTEGER) = 27 AND CAST(substr(go_version, 8) AS INTEGER) >= 3)
              OR (CAST(substr(go_version, 5) AS INTEGER) = 26 AND CAST(substr(go_version, 8) AS INTEGER) >= 10)
            THEN 'FIXED_GO'
            ELSE 'REBUILD with Go>=1.27.3/1.26.10' END
FROM go_binaries
UNION ALL
SELECT 'host', name, version || ' ' || platform_like, 'INFO'
FROM os_version;
