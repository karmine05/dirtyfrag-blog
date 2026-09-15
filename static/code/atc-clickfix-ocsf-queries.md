<!--
ATC ClickFix triage bundle — OCSF-mapped query pack
Companion post: https://karmine05.github.io/dirtyfrag-blog/posts/atc-clickfix-mcp-triage/
Requires the Fleet agent options in atc-clickfix-fleet-agent-options.yml.
All tables and columns validated against fleetdm.com/tables on 2026-09-14.
-->

# Reconstructing a browser-to-terminal compromise with Fleet, osquery and OCSF

A query pack for answering one question in stages: *was this user phished, and if so, how far did it go?*

Each query maps its output to an [OCSF](https://schema.ocsf.io/) event class so results drop into a SIEM without reshaping, and decodes every raw integer into something a human can read without a lookup table.

---

## The decision tree

The queries below answer these in order. Each stage only matters if the previous one is true.

| Stage | Question | Source table | OCSF class |
|---|---|---|---|
| 1 | Did they reach the page at all? | `chrome_url_history` | 4002 HTTP Activity |
| 2 | Did they *interact*, or just load it? | `chrome_url_history` (transition + dwell) | 4002 HTTP Activity |
| 3 | Did anything land on disk? | `quarantine_items`, `chrome_download_history` + `file`, `file` scan | 4010 Network File Activity |
| 4 | Did anything **execute**? | `shell_history`, `es_process_events` | 1007 Process Activity |
| 5 | Do the timestamps line up? | all of the above | — |

Stage 4 is the one that matters for ClickFix specifically. The technique delivers by putting a command on the clipboard and instructing the victim to paste it into Terminal — it never touches the browser's download path and never acquires a quarantine xattr. A clean stage 3 does **not** mean a clean host.

---

## Query 1 — Navigation: visited vs. interacted

OCSF class 4002 (HTTP Activity). `activity_id` follows OCSF's HTTP method enum: 3 = Get, 6 = Post. A Chrome `FORM_SUBMIT` transition is the only one that reliably implies a POST.

```sql
-- OCSF 4002 : HTTP Activity - browser navigation, last 6 hours
SELECT
  4002                                                                          AS class_uid,
  'HTTP Activity'                                                               AS class_name,
  datetime(CAST(v.visit_time AS BIGINT)/1000000 - 11644473600, 'unixepoch')     AS time_utc,
  CASE WHEN CAST(v.transition AS INTEGER) & 255 = 7 THEN 6 ELSE 3 END           AS activity_id,
  CASE WHEN CAST(v.transition AS INTEGER) & 255 = 7 THEN 'Post' ELSE 'Get' END  AS http_method,
  v.url                                                                         AS url_text,
  v.title                                                                       AS resource_name,

  -- Chrome PageTransition core type (low 8 bits), decoded
  CASE CAST(v.transition AS INTEGER) & 255
    WHEN 0  THEN 'link_click'
    WHEN 1  THEN 'typed_in_address_bar'
    WHEN 2  THEN 'bookmark'
    WHEN 3  THEN 'auto_subframe'
    WHEN 4  THEN 'manual_subframe'
    WHEN 5  THEN 'omnibox_suggestion'
    WHEN 6  THEN 'start_page_or_home'
    WHEN 7  THEN 'form_submitted'
    WHEN 8  THEN 'page_reload'
    WHEN 9  THEN 'keyword_search'
    WHEN 10 THEN 'keyword_generated'
    ELSE 'unknown_' || CAST(CAST(v.transition AS INTEGER) & 255 AS TEXT)
  END                                                                           AS navigation_type,

  -- Qualifier bits (high bits) separate "the human did this" from "the page did this"
  --   0xC0000000 = IS_REDIRECT_MASK (client 0x40000000 | server 0x80000000)
  --   0x01000000 = FORWARD_BACK
  CASE
    WHEN CAST(v.transition AS INTEGER) & 3221225472 != 0 THEN 'automatic_redirect'
    WHEN CAST(v.transition AS INTEGER) & 16777216   != 0 THEN 'back_or_forward_button'
    WHEN CAST(v.transition AS INTEGER) & 255 IN (0,1,2,5,7,9) THEN 'user_initiated'
    ELSE 'browser_initiated'
  END                                                                           AS initiated_by,

  -- visit_duration is MICROseconds
  ROUND(CAST(v.visit_duration AS BIGINT)/1000000.0, 1)                          AS duration_seconds,
  CASE
    WHEN CAST(v.visit_duration AS BIGINT) = 0         THEN 'no_dwell'
    WHEN CAST(v.visit_duration AS BIGINT) < 2000000   THEN 'glance_under_2s'
    WHEN CAST(v.visit_duration AS BIGINT) < 30000000  THEN 'read_under_30s'
    WHEN CAST(v.visit_duration AS BIGINT) < 300000000 THEN 'engaged_under_5m'
    ELSE 'sustained_over_5m'
  END                                                                           AS engagement,

  -- the stage 1 vs stage 2 verdict
  CASE
    WHEN CAST(v.transition AS INTEGER) & 255 = 7
      THEN 'INTERACTED - submitted data to the page'
    WHEN CAST(v.transition AS INTEGER) & 3221225472 != 0
      THEN 'PASSIVE - arrived via redirect, not a deliberate click'
    WHEN CAST(v.transition AS INTEGER) & 255 IN (0,1,2,5,9)
         AND CAST(v.visit_duration AS BIGINT) > 2000000
      THEN 'ENGAGED - deliberate navigation with real dwell time'
    ELSE 'VISITED - page loaded, no interaction signal'
  END                                                                           AS verdict,

  v.visit_count                                                                 AS url_total_visits
FROM chrome_url_history v
WHERE CAST(v.visit_time AS BIGINT)/1000000 - 11644473600 > (strftime('%s','now') - 21600)
ORDER BY CAST(v.visit_time AS BIGINT) ASC;
```

**Reading it.** `form_submitted` is the strongest single indicator that a human typed something and hit a button. `automatic_redirect` with `no_dwell` is the signature of a traffic-distribution chain and should not be counted as a user action. A row that is `link_click` + `no_dwell` usually means the page bounced onward immediately.

---

## Query 2 — What landed on disk

OCSF class 4010 (Network File Activity), `activity_id` 2 = Download. Three separate queries, because no single source is complete and merging them hides which evidence came from where. Run all three and cross-reference.

`quarantine_items` reads `LSQuarantineEventsV2`, which uses **Mac absolute time** — seconds since 2001-01-01, so the offset is `+ 978307200`, not the Chrome `- 11644473600`. Mixing these up is the single easiest way to get a silently empty result.

### 2a — Quarantine events

Nine identical-looking rows with no filename and no URL is the failure mode this query has to avoid. The event record on its own carries no file path, and `sender_name`/`sender_address` are only ever populated for Mail and Messages attachments — for a browser download they are always blank. So the projection has to lead with the fields that actually discriminate between events: the event UUID and the type number.

```sql
-- OCSF 4010 : Network File Activity / Download - quarantine events
WITH qi AS (
  SELECT
    id,
    type,
    agent_name,
    agent_bundle_identifier,
    timestamp,
    NULLIF(TRIM(data_url),   '') AS data_url,
    NULLIF(TRIM(origin_url), '') AS origin_url,
    NULLIF(TRIM(sender_name),    '') AS sender_name,
    NULLIF(TRIM(sender_address), '') AS sender_address,
    -- drop any query string before taking the basename
    CASE
      WHEN TRIM(data_url) = '' THEN NULL
      WHEN INSTR(data_url, '?') > 0 THEN SUBSTR(data_url, 1, INSTR(data_url, '?') - 1)
      ELSE data_url
    END AS clean_url
  FROM quarantine_items
)
SELECT
  4010                                                          AS class_uid,
  'Network File Activity'                                       AS class_name,
  2                                                             AS activity_id,
  'Download'                                                    AS activity_name,
  datetime(CAST(q.timestamp AS BIGINT) + 978307200,'unixepoch') AS time_utc,
  q.id                                                          AS quarantine_event_uid,
  q.agent_name                                                  AS actor_process_name,
  q.agent_bundle_identifier                                     AS actor_process_uid,

  -- LSQuarantineTypeNumber, decoded
  CASE CAST(q.type AS INTEGER)
    WHEN 0 THEN 'web_download'
    WHEN 1 THEN 'other_download'
    WHEN 2 THEN 'email_attachment'
    WHEN 3 THEN 'instant_message_attachment'
    WHEN 4 THEN 'calendar_event_attachment'
    WHEN 5 THEN 'other_attachment'
    ELSE 'unknown_' || COALESCE(CAST(q.type AS TEXT), 'null')
  END                                                           AS download_source_type,

  q.data_url                                                    AS url_text,
  q.origin_url                                                  AS http_request_referrer,
  CASE WHEN q.clean_url IS NULL THEN NULL
       ELSE REPLACE(q.clean_url,
                    RTRIM(q.clean_url, REPLACE(q.clean_url, '/', '')), '')
  END                                                           AS file_name,

  -- sender_* only populate for Mail / Messages sourced quarantine events
  CASE WHEN CAST(q.type AS INTEGER) IN (2,3)
       THEN COALESCE(q.sender_name, q.sender_address) END       AS sender,

  -- makes "blank" explicit instead of ambiguous
  TRIM(
    CASE WHEN q.data_url   IS NOT NULL THEN 'data_url '   ELSE '' END ||
    CASE WHEN q.origin_url IS NOT NULL THEN 'origin_url ' ELSE '' END ||
    CASE WHEN q.sender_name IS NOT NULL THEN 'sender_name ' ELSE '' END
  )                                                             AS populated_url_fields,

  'quarantine_event'                                            AS evidence_source
FROM qi q
WHERE CAST(q.timestamp AS BIGINT) + 978307200 > (strftime('%s','now') - 21600)
ORDER BY CAST(q.timestamp AS BIGINT) ASC;
```

`populated_url_fields` is the column to read first. On the host this pack was built against, it came back empty on all nine Chrome `web_download` events: the event UUID, type, agent and timestamp were all written, the URL strings were not. That is a property of the data source, not the query. Treat 2a as proof that a download *event* occurred and when; get the URL and file path from 2a-linked, which reads them from a different place.

Run this once with no time filter to see what the table actually holds before trusting a filtered result:

```sql
SELECT * FROM quarantine_items ORDER BY CAST(timestamp AS BIGINT) DESC LIMIT 20;
```

### 2a-linked — URL and file path from the file's own extended attributes

When the LaunchServices database has no URL, the file usually still does. Chrome writes two extended attributes onto every download:

- `com.apple.metadata:kMDItemWhereFroms` — a plist array of `[download_url, referrer_url]`
- `com.apple.quarantine` — `<flags>;<hex epoch>;<agent>;<event UUID>`

osquery's `extended_attributes` table parses both rather than returning them raw. `kMDItemWhereFroms` becomes one row per URL under the key `where_from`, in array order. `com.apple.quarantine` becomes `quarantine_agent`, `quarantine_type`, `quarantine_timestamp` and `quarantine_event_id`. The raw key name `com.apple.quarantine` is **not** returned, which is why a join on `x.key = 'com.apple.quarantine'` yields nothing.

See what the parser actually emits for one directory before trusting the shaped query:

```sql
SELECT path, key, value
FROM extended_attributes
WHERE directory LIKE '/Users/%/Downloads'
ORDER BY path, key;
```

Then the OCSF-shaped version. `quarantine_event_id` is the join key back to `quarantine_items.id`; `where_from` supplies the URLs the database lacks.

```sql
-- OCSF 4010 : Network File Activity / Download
-- Source: per-file xattrs (kMDItemWhereFroms + com.apple.quarantine), joined to the event record
WITH xa AS (
  SELECT
    x.path,
    MAX(CASE WHEN x.key = 'quarantine_event_id'  THEN x.value END) AS event_id,
    MAX(CASE WHEN x.key = 'quarantine_agent'     THEN x.value END) AS agent,
    MAX(CASE WHEN x.key = 'quarantine_type'      THEN x.value END) AS q_type,
    MAX(CASE WHEN x.key = 'quarantine_timestamp' THEN x.value END) AS q_timestamp_raw,
    -- where_from rows arrive in plist order: [download_url, referrer_url].
    -- CHAR(30) is the ASCII record separator - it cannot appear in a URL.
    GROUP_CONCAT(CASE WHEN x.key = 'where_from' THEN x.value END, CHAR(30)) AS where_from
  FROM extended_attributes x
  WHERE x.directory LIKE '/Users/%/Downloads'
     OR x.directory = '/Users/Shared'
     OR x.directory = '/tmp'
  GROUP BY x.path
)
SELECT
  4010                                                             AS class_uid,
  'Network File Activity'                                          AS class_name,
  2                                                                AS activity_id,
  'Download'                                                       AS activity_name,
  datetime(f.btime, 'unixepoch')                                   AS time_utc,
  xa.event_id                                                      AS quarantine_event_uid,
  COALESCE(xa.agent, q.agent_name)                                 AS actor_process_name,

  CASE CAST(COALESCE(xa.q_type, q.type) AS INTEGER)
    WHEN 0 THEN 'web_download'
    WHEN 1 THEN 'other_download'
    WHEN 2 THEN 'email_attachment'
    WHEN 3 THEN 'instant_message_attachment'
    WHEN 4 THEN 'calendar_event_attachment'
    WHEN 5 THEN 'other_attachment'
    ELSE 'unknown'
  END                                                              AS download_source_type,

  -- first where_from entry
  CASE
    WHEN xa.where_from IS NULL                      THEN NULL
    WHEN INSTR(xa.where_from, CHAR(30)) = 0         THEN xa.where_from
    ELSE SUBSTR(xa.where_from, 1, INSTR(xa.where_from, CHAR(30)) - 1)
  END                                                              AS url_text,
  -- second where_from entry
  CASE
    WHEN xa.where_from IS NULL                      THEN NULL
    WHEN INSTR(xa.where_from, CHAR(30)) = 0         THEN NULL
    ELSE SUBSTR(xa.where_from, INSTR(xa.where_from, CHAR(30)) + 1)
  END                                                              AS http_request_referrer,

  f.path                                                           AS file_path,
  f.filename                                                       AS file_name,
  f.size                                                           AS file_size_bytes,
  f.mode                                                           AS file_mode,
  h.sha256                                                         AS file_sha256,

  -- did the LaunchServices DB also record this event?
  CASE WHEN q.id IS NOT NULL THEN 1 ELSE 0 END                     AS event_in_quarantine_db,
  CASE WHEN q.id IS NOT NULL
       THEN datetime(CAST(q.timestamp AS BIGINT) + 978307200, 'unixepoch') END
                                                                   AS quarantine_db_time_utc,
  'file_xattr'                                                     AS evidence_source
FROM xa
JOIN file f            ON f.path = xa.path
LEFT JOIN hash h       ON h.path = xa.path
LEFT JOIN quarantine_items q
       ON UPPER(q.id) = UPPER(xa.event_id)
WHERE f.type = 'regular'
  AND f.btime > (strftime('%s','now') - 21600)
ORDER BY f.btime ASC;
```

**Reading it.** `url_text` populated with `event_in_quarantine_db = 1` is the full picture: the browser recorded where the file came from, and LaunchServices logged the event. `url_text` populated with `event_in_quarantine_db = 0` means the file was tagged but the event record is gone or was never written. `url_text` NULL with a `quarantine_event_uid` present means the file carries a quarantine tag but no `kMDItemWhereFroms` — typical of a `curl` download that was later manually quarantined, or of a file whose metadata was stripped.

`extended_attributes` requires a `path` or `directory` constraint and will not scan unbounded. If the `LIKE` on `directory` is rejected on your osquery build, replace it with literal directories. `GROUP_CONCAT` ordering is not guaranteed by the SQL standard but follows row order in SQLite, which for this table is plist order.

### 2b — Chrome download records, enriched from disk

Chrome records the target path; the filesystem supplies the creation time, size and hash that the default ATC column set does not expose. This is the query that answers "what was downloaded and when" from Chrome's own view.

```sql
-- OCSF 4010 : Network File Activity / Download - Chrome records joined to disk
SELECT
  4010                                                        AS class_uid,
  'Network File Activity'                                     AS class_name,
  2                                                           AS activity_id,
  'Download'                                                  AS activity_name,
  datetime(f.btime, 'unixepoch')                              AS time_utc,
  'Google Chrome'                                             AS actor_process_name,
  d.target_path                                               AS file_path,
  f.filename                                                  AS file_name,
  f.size                                                      AS file_size_bytes,
  f.mode                                                      AS file_mode,
  datetime(f.mtime, 'unixepoch')                              AS file_modified_utc,
  h.sha256                                                    AS file_sha256,
  d.current_path                                              AS file_original_path,
  CASE WHEN d.current_path != d.target_path THEN 1 ELSE 0 END AS was_relocated,
  'chrome_download_record'                                    AS evidence_source
FROM chrome_download_history d
JOIN file f ON f.path = d.target_path
LEFT JOIN hash h ON h.path = f.path
ORDER BY f.btime ASC;
```

The join supplies the path constraint that osquery's `file` table requires. Constraint propagation through a join is not guaranteed on every osquery build, so if this returns nothing on a host where `chrome_download_history` has rows, fall back to a two-step: pull the bare records, then constrain `file` explicitly.

```sql
-- 2b step 1: bare Chrome records
SELECT id, current_path, target_path FROM chrome_download_history;
```

```sql
-- 2b step 2: explicit path constraint using the target_path values from step 1
SELECT f.path, f.filename, f.size, f.mode,
       datetime(f.btime, 'unixepoch') AS created_utc,
       datetime(f.mtime, 'unixepoch') AS modified_utc,
       h.sha256
FROM file f LEFT JOIN hash h ON h.path = f.path
WHERE f.path IN ('/Users/<user>/Downloads/<name>', '/Users/<user>/Downloads/<name2>');
```

Every time value in 2b comes from the filesystem, because `chrome_download_history` carries no timestamp in the default column set. Exposing `downloads.start_time` fixes that — see the prerequisites.

### 2c — Filesystem scan of download and staging directories

Catches what neither browser source sees: `curl` and `wget` payloads, which never acquire a quarantine xattr and never enter Chrome's download table. This is the query that matters for clipboard-delivered execution.

```sql
-- OCSF 4010 : Network File Activity / Download - filesystem artifacts
SELECT
  4010                                                  AS class_uid,
  'Network File Activity'                               AS class_name,
  2                                                     AS activity_id,
  'Download'                                            AS activity_name,
  datetime(f.btime, 'unixepoch')                        AS time_utc,
  f.path                                                AS file_path,
  f.filename                                            AS file_name,
  f.size                                                AS file_size_bytes,
  f.mode                                                AS file_mode,
  f.uid                                                 AS file_owner_uid,
  datetime(f.mtime, 'unixepoch')                        AS file_modified_utc,
  h.sha256                                              AS file_sha256,
  CASE
    WHEN f.path LIKE '/Users/Shared/%' THEN 'world_writable_staging'
    WHEN f.path LIKE '/tmp/%'          THEN 'temp_staging'
    ELSE 'user_downloads'
  END                                                   AS location_class,
  CASE WHEN f.filename LIKE '.%' THEN 1 ELSE 0 END      AS is_hidden,
  'filesystem_artifact'                                 AS evidence_source
FROM file f
LEFT JOIN hash h ON h.path = f.path
WHERE (f.path LIKE '/Users/%/Downloads/%'
    OR f.path LIKE '/Users/Shared/%'
    OR f.path LIKE '/tmp/%')
  AND f.btime > (strftime('%s','now') - 21600)
  AND f.type = 'regular'
ORDER BY f.btime ASC;
```

**Cross-referencing the three.** A file in 2c with no matching row in 2a or 2b arrived outside the browser entirely — that is the clipboard-delivery signature. A row in 2a with no counterpart in 2b means the download was quarantined but Chrome was not the agent. A row in 2b with no row in 2a means Chrome wrote the file without a quarantine xattr, which is worth explaining on its own.

---

## Query 3 — What executed

OCSF class 1007 (Process Activity), `activity_id` 1 = Launch. `shell_history` requires a join against `users`; querying it standalone returns nothing.

```sql
-- OCSF 1007 : Process Activity / Launch - reconstructed from shell history
SELECT
  1007                                                        AS class_uid,
  'Process Activity'                                          AS class_name,
  1                                                           AS activity_id,
  'Launch'                                                    AS activity_name,
  CASE WHEN s.time = 0 THEN NULL
       ELSE datetime(s.time, 'unixepoch') END                 AS time_utc,
  u.username                                                  AS actor_user_name,
  u.uid                                                       AS actor_user_uid,
  s.history_file                                              AS metadata_log_name,
  s.command                                                   AS process_cmd_line,

  CASE
    WHEN s.command LIKE '%osascript%'                          THEN 'applescript_execution'
    WHEN s.command LIKE '%pbpaste%'                            THEN 'clipboard_read'
    WHEN s.command LIKE '%base64 -d%'
      OR s.command LIKE '%base64 --decode%'                    THEN 'encoded_payload_decode'
    WHEN s.command LIKE '%curl%|%sh%' OR s.command LIKE '%curl%|%bash%'
      OR s.command LIKE '%wget%|%sh%'                          THEN 'remote_script_piped_to_shell'
    WHEN s.command LIKE '%curl %' OR s.command LIKE '%wget %'  THEN 'remote_content_fetch'
    WHEN s.command LIKE '%tccutil%' OR s.command LIKE '%TCC.db%' THEN 'tcc_manipulation'
    WHEN s.command LIKE '%launchctl load%'
      OR s.command LIKE '%LaunchAgents%'
      OR s.command LIKE '%LaunchDaemons%'                      THEN 'persistence_mechanism'
    WHEN s.command LIKE '%chmod +x%'                           THEN 'make_executable'
    WHEN s.command LIKE '%/Users/Shared/%'
      OR s.command LIKE '%/tmp/%'                              THEN 'staging_directory_use'
    WHEN s.command LIKE 'sudo %'                               THEN 'privileged_execution'
    ELSE 'other'
  END                                                         AS behavior,

  -- OCSF severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical
  CASE
    WHEN s.command LIKE '%osascript%'
      OR s.command LIKE '%base64 -d%'
      OR s.command LIKE '%curl%|%sh%'
      OR s.command LIKE '%curl%|%bash%'
      OR s.command LIKE '%pbpaste%'                            THEN 5
    WHEN s.command LIKE '%tccutil%'
      OR s.command LIKE '%LaunchAgents%'
      OR s.command LIKE '%LaunchDaemons%'
      OR s.command LIKE '%chmod +x%'                           THEN 4
    WHEN s.command LIKE '%curl %' OR s.command LIKE '%wget %'
      OR s.command LIKE 'sudo %'                               THEN 3
    ELSE 1
  END                                                         AS severity_id,

  -- zsh escapes embedded newlines with a trailing backslash when writing history.
  -- Indicates a multi-line command; a paste is one cause, a typed loop is another.
  CASE WHEN s.command LIKE '%\' THEN 1 ELSE 0 END              AS multiline_fragment
FROM users u
CROSS JOIN shell_history s USING (uid)
WHERE u.directory LIKE '/Users/%'
ORDER BY u.username, s.history_file;
```

**Do not add a time filter to this query.** See the caveats — `time` is almost always 0.

### The same thing from EndpointSecurity, once configured

`es_process_events` gives real timestamps, parent PIDs and code-signing state — everything `shell_history` cannot. It only works if `events_expiry` is raised and a scheduled query is shipping the events (see prerequisites).

```sql
-- OCSF 1007 : Process Activity / Launch - from EndpointSecurity
SELECT
  1007                                        AS class_uid,
  'Process Activity'                          AS class_name,
  1                                           AS activity_id,
  'Launch'                                    AS activity_name,
  datetime(e.time, 'unixepoch')               AS time_utc,
  e.username                                  AS actor_user_name,
  e.path                                      AS process_file_path,
  e.cmdline                                   AS process_cmd_line,
  e.pid                                       AS process_pid,
  e.parent                                    AS actor_process_pid,
  e.cwd                                       AS process_working_directory,
  e.signing_id                                AS process_file_signature_id,
  e.team_id                                   AS process_file_signature_developer_uid,
  CASE e.platform_binary WHEN 1 THEN 'apple_signed' ELSE 'third_party' END AS provenance,
  e.codesigning_flags                         AS signature_flags,
  CASE
    WHEN e.codesigning_flags LIKE '%NOT_VALID%' THEN 5
    WHEN e.codesigning_flags LIKE '%ADHOC%'     THEN 4
    WHEN e.platform_binary = 0                  THEN 3
    ELSE 1
  END                                         AS severity_id
FROM es_process_events e
WHERE e.time > (strftime('%s','now') - 21600)
  AND (e.path LIKE '%/sh' OR e.path LIKE '%/zsh' OR e.path LIKE '%/bash'
    OR e.path LIKE '%osascript' OR e.path LIKE '%curl' OR e.path LIKE '%python%')
ORDER BY e.time ASC;
```

---

## Query 4 — Stitching the timeline

One ordered sequence across navigation, download and filesystem activity. This is the view that shows a browser visit followed minutes later by a file appearing in a staging directory.

```sql
-- Unified incident timeline, last 6 hours
SELECT
  datetime(CAST(v.visit_time AS BIGINT)/1000000 - 11644473600, 'unixepoch') AS time_utc,
  'browser'                                                                 AS stream,
  CASE CAST(v.transition AS INTEGER) & 255
    WHEN 7 THEN 'form_submitted' WHEN 0 THEN 'link_click'
    WHEN 1 THEN 'typed_url'      WHEN 8 THEN 'page_reload'
    ELSE 'navigation' END                                                   AS action,
  v.url                                                                     AS detail
FROM chrome_url_history v
WHERE CAST(v.visit_time AS BIGINT)/1000000 - 11644473600 > (strftime('%s','now') - 21600)

UNION ALL

SELECT
  datetime(CAST(q.timestamp AS BIGINT) + 978307200, 'unixepoch'),
  'download', 'file_quarantined',
  q.agent_name || ' <- ' || q.data_url
FROM quarantine_items q
WHERE CAST(q.timestamp AS BIGINT) + 978307200 > (strftime('%s','now') - 21600)

UNION ALL

SELECT
  datetime(f.btime, 'unixepoch'),
  'filesystem', 'file_created',
  f.path || '  (' || CAST(f.size AS TEXT) || ' bytes)'
FROM file f
WHERE (f.path LIKE '/Users/%/Downloads/%'
    OR f.path LIKE '/Users/Shared/%'
    OR f.path LIKE '/tmp/%')
  AND f.btime > (strftime('%s','now') - 21600)
  AND f.type = 'regular'

ORDER BY 1 ASC;
```

### Recovering time for shell history

`shell_history` has no usable timestamps, but Terminal.app writes per-session history files whose *filesystem* timestamps are real. These bound each shell session, letting you place a block of commands against the browser timeline even without per-command times:

```sql
SELECT
  f.filename                             AS session_file,
  datetime(f.btime, 'unixepoch')         AS session_started_utc,
  datetime(f.mtime, 'unixepoch')         AS session_last_write_utc,
  f.size                                 AS bytes
FROM file f
WHERE f.path LIKE '/Users/%/.zsh_sessions/%'
ORDER BY f.mtime DESC;
```

---

## Correctness caveats

These are the things that make a query return a confidently wrong answer rather than an obvious error.

**Two different epochs.** Chrome history is microseconds since 1601-01-01 (`/1000000 - 11644473600`). LaunchServices quarantine is seconds since 2001-01-01 (`+ 978307200`). Filesystem `btime`/`mtime` are plain Unix epoch. Using the wrong one returns zero rows, not an error.

**ATC columns are TEXT.** Every auto-table-construction column arrives as text regardless of what SQLite stored. Arithmetic and bitwise operations need an explicit `CAST(... AS BIGINT)` or `CAST(... AS INTEGER)`; without it you get silent implicit-conversion surprises on the bitmask comparisons.

**ATC has no WHERE pushdown.** The configured ATC query runs in full — for `chrome_url_history` that is every visit ever recorded — and osquery filters afterward. On a long-lived profile this is a large read. It is also why these queries are slower than a native table and more likely to hit a live-query timeout.

**Chrome locks its History database.** osquery reads the SQLite file directly. If Chrome is running, `chrome_url_history` and `chrome_download_history` may return zero rows or a lock error. A zero-row result while the browser is open is not evidence of no activity.

**`chrome_download_history` cannot be time-bounded.** With the columns most configs expose (`id`, `current_path`, `target_path`) there is no timestamp at all. Any "downloads in the last N hours" question has to come from `quarantine_items` or filesystem `btime`.

**The quarantine database may hold no URLs at all.** On current Chrome the `LSQuarantineEventsV2` row is written with event ID, type, agent and timestamp but `LSQuarantineDataURLString` and `LSQuarantineOriginURLString` left NULL. The URLs live in the file's `kMDItemWhereFroms` extended attribute instead. A blank `url_text` from `quarantine_items` is expected, not a query failure; use `extended_attributes` (2a-linked).

**Quarantine only sees quarantine-aware downloads.** Files fetched with `curl`/`wget` never get the `com.apple.quarantine` xattr and never appear in `quarantine_items`. This is exactly how clipboard-delivered payloads arrive.

**`shell_history.time` is 0 without `EXTENDED_HISTORY`.** zsh writes bare command lines by default. Filtering on `time` returns nothing and reads as "no activity." Verify the on-disk format directly:

```sql
SELECT line FROM file_lines WHERE path = '/Users/<user>/.zsh_history' LIMIT 5;
```

Lines beginning `: 1757866103:0;` mean extended history is on. Bare commands mean it is off.

**zsh flushes history on shell exit.** Without `INC_APPEND_HISTORY`, commands from a still-open Terminal window are not on disk yet and will not appear.

**`from_visit` is unresolvable in the default ATC config.** The common config exposes `urls.id` as `id` but never exposes `visits.id`, while `from_visit` references `visits.id`. Referrer chains cannot be walked until the config exposes both.

**Trailing backslashes indicate a multi-line command, not specifically a paste.** zsh escapes embedded newlines when writing history. A hand-typed `for` loop produces the same artifact.

---

## Configuration prerequisites

These queries are only as good as the agent options behind them. Five changes materially improve what is recoverable.

**1. Expose download metadata.** The default column set (`id`, `current_path`, `target_path`) has no timestamp, so downloads cannot be time-bounded. Expose the rest of the `downloads` table, and take the final download URL from `downloads_url_chains` (the last `chain_index` is the URL the bytes actually came from, after any redirects):

```yaml
chrome_download_history:
  path: /Users/%%/Library/Application Support/Google/Chrome/%%/History
  query: >-
    SELECT d.id id, d.guid guid, d.current_path current_path,
    d.target_path target_path, d.start_time start_time, d.end_time
    end_time, d.received_bytes received_bytes, d.total_bytes
    total_bytes, d.state state, d.danger_type danger_type,
    d.interrupt_reason interrupt_reason, d.opened opened, d.mime_type
    mime_type, d.referrer referrer, d.tab_url tab_url,
    d.tab_referrer_url tab_referrer_url, d.by_ext_name by_ext_name,
    c.url download_url FROM downloads d LEFT JOIN downloads_url_chains c
    ON c.id = d.id AND c.chain_index = (SELECT MAX(chain_index) FROM
    downloads_url_chains WHERE id = d.id)
  columns:
    - id
    - guid
    - current_path
    - target_path
    - start_time
    - end_time
    - received_bytes
    - total_bytes
    - state
    - danger_type
    - interrupt_reason
    - opened
    - mime_type
    - referrer
    - tab_url
    - tab_referrer_url
    - by_ext_name
    - download_url
```

`start_time` and `end_time` use the Chrome epoch, same conversion as `visit_time`. `tab_url` is the page the download was started from; `referrer` is the HTTP referrer; `download_url` is where the bytes came from. `state` decodes as 0 in-progress, 1 complete, 2 cancelled, 3 interrupted. `danger_type` 0 is not-dangerous; anything else means Safe Browsing flagged it — 1 dangerous file, 2 dangerous URL, 3 dangerous content, 4 maybe dangerous content, 5 uncommon content, 6 user validated (the user clicked through the warning), 7 dangerous host, 8 potentially unwanted. Edge shares this schema exactly; the same query works against its `History` file.

**2. Expose `visits.id` in `chrome_url_history`** so `from_visit` resolves and redirect chains can be reconstructed. Add `visits.id visit_id` to the query and `visit_id` to the `columns` list.

**3. Raise `events_expiry`.** A value of `600` retains ten minutes of evented data. The osquery default is `86400`. At 600, any investigation starting more than ten minutes after the fact finds an empty `es_process_events` table. Raise `events_max` alongside it — at the default 50000 an active workstation fills the EndpointSecurity buffer in well under a day, and the oldest events are dropped regardless of expiry. 250000 is a starting point; check `SELECT name, events FROM osquery_events` on a busy host after a day and adjust.

**4. Schedule a query against `es_process_events`.** Live queries only ever see the current in-memory buffer. Retrospective hunting requires the events to have been logged to your TLS logger endpoint at the time they occurred.

**5. Confirm TCC approval for osqueryd.** `disable_endpointsecurity: false` declares intent, not consent. Without Full Disk Access and the EndpointSecurity entitlement approved, `es_process_events` is empty regardless of every other setting. Baseline it:

```sql
SELECT COUNT(*) AS events,
       datetime(MIN(time),'unixepoch') AS oldest_utc,
       datetime(MAX(time),'unixepoch') AS newest_utc
FROM es_process_events;
```

A zero count on an active host means the entitlement is not granted. The gap between `oldest_utc` and `newest_utc` is your real retention window, whatever the config claims.

**6. Enable timestamped shell history** on hosts used for detonation work:

```sh
echo 'setopt EXTENDED_HISTORY'    >> ~/.zshrc
echo 'setopt INC_APPEND_HISTORY'  >> ~/.zshrc
```

Neither setting backfills. Existing entries stay timestampless permanently.

---

## A note on running these

Live queries against ATC tables are slow. If the agent's `distributed_interval` is 60 seconds, allow **at least 90 seconds** for results before treating a run as failed — the Fleet UI waits indefinitely, but API clients and agent integrations frequently give up early and report a timeout on a perfectly healthy host.
