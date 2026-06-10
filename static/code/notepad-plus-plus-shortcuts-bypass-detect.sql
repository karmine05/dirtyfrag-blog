-- Notepad++ trusted-directory bypass (GHSA-p58x-r3c9-x9p6)
-- Identify Notepad++ on a Windows host, whether installed or portable.
--
-- Advisory: https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-p58x-r3c9-x9p6
-- Affected: v8.9.6.1   Patched: v8.9.6.2   (advisory has no assigned CVE)
--
-- The `file` rows catch the binary on disk (installed AND portable copies in
-- common locations). The `processes` row catches a running portable copy whose
-- path may sit outside the locations checked below.
--
-- Note: the file table expands roughly one directory level per % in a LIKE,
-- so deep/uncommon portable locations (e.g. C:\Tools\npp\) are not covered.
-- Add paths as needed for your environment.

SELECT 'file' AS src, path, file_version, product_version FROM file
WHERE path IN ('C:\Program Files\Notepad++\notepad++.exe',
               'C:\Program Files (x86)\Notepad++\notepad++.exe')
   OR path LIKE 'C:\Users\%\Downloads\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\Desktop\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\Documents\%\notepad++.exe'
   OR path LIKE 'C:\Users\%\AppData\Local\%\notepad++.exe'
UNION ALL
SELECT 'proc' AS src, path, '' , '' FROM processes WHERE LOWER(path) LIKE '%notepad++.exe%';
