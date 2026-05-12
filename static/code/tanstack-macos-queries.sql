-- ============================================================================
-- Mini Shai-Hulud Mass-Compromise (CVE-2026-45321 & expanded campaign) — macOS
-- Hybrid: npm_packages (exposure) + file (payload/persistence) + launchd + processes
--
-- Source: Socket.dev affected-versions feed (mirrored via champjss/mini-shai-
-- hulud-checker-20260512, snapshot 2026-05-12). Covers 175 npm packages /
-- 406 versions across 17 namespaces (@tanstack, @uipath, @squawk, @mistralai,
-- @opensearch-project, @cap-js, @draftlab, @draftauth, @tallyui, @beproduct,
-- @taskflow-corp, @tolka, @mesadev, @ml-toolkit-ts, @supersurkhet, @dirigible-ai,
-- plus 12 unscoped packages).
--
-- Validated 2026-05-12 against host_id=1497. Parses cleanly.
--
-- NOTE: Socket.dev's feed updates as the campaign evolves. Regenerate from
-- the source CSV periodically.
-- ============================================================================

-- EXPOSURE: known-bad versions in globally-discovered npm trees.
-- Default-discovery walker covers ~/.npm-global, /usr/local/lib, /opt/homebrew/lib.
-- Project-local exposure is caught by the file-based router_init.js hunt below.
SELECT 'EXPOSURE_global_pkg_version' AS indicator,
       name || '@' || version || '  ->  ' || path AS path
FROM npm_packages
   WHERE (name = '@beproduct/nestjs-auth' AND version IN ('0.1.10', '0.1.11', '0.1.12', '0.1.13', '0.1.14', '0.1.15', '0.1.16', '0.1.17', '0.1.18', '0.1.19', '0.1.2', '0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7', '0.1.8', '0.1.9'))
      OR (name = '@cap-js/db-service' AND version = '2.10.1')
      OR (name = '@cap-js/postgres' AND version = '2.2.2')
      OR (name = '@cap-js/sqlite' AND version = '2.2.2')
      OR (name = '@dirigible-ai/sdk' AND version IN ('0.6.2', '0.6.3'))
      OR (name = '@draftauth/client' AND version IN ('0.2.1', '0.2.2'))
      OR (name = '@draftauth/core' AND version IN ('0.13.1', '0.13.2'))
      OR (name = '@draftlab/auth' AND version IN ('0.24.1', '0.24.2'))
      OR (name = '@draftlab/auth-router' AND version IN ('0.5.1', '0.5.2'))
      OR (name = '@draftlab/db' AND version IN ('0.16.1', '0.16.2'))
      OR (name = '@mesadev/rest' AND version = '0.28.3')
      OR (name = '@mesadev/saguaro' AND version = '0.4.22')
      OR (name = '@mesadev/sdk' AND version = '0.28.3')
      OR (name = '@mistralai/mistralai' AND version IN ('2.2.2', '2.2.3', '2.2.4'))
      OR (name = '@mistralai/mistralai-azure' AND version IN ('1.7.1', '1.7.2', '1.7.3'))
      OR (name = '@mistralai/mistralai-gcp' AND version IN ('1.7.1', '1.7.2', '1.7.3'))
      OR (name = '@ml-toolkit-ts/preprocessing' AND version IN ('1.0.2', '1.0.3'))
      OR (name = '@ml-toolkit-ts/xgboost' AND version IN ('1.0.3', '1.0.4'))
      OR (name = '@opensearch-project/opensearch' AND version = '3.6.2')
      OR (name = '@squawk/airport-data' AND version IN ('0.7.4', '0.7.5', '0.7.6', '0.7.7', '0.7.8'))
      OR (name = '@squawk/airports' AND version IN ('0.6.2', '0.6.3', '0.6.4', '0.6.5', '0.6.6'))
      OR (name = '@squawk/airspace' AND version IN ('0.8.1', '0.8.2', '0.8.3', '0.8.4', '0.8.5'))
      OR (name = '@squawk/airspace-data' AND version IN ('0.5.3', '0.5.4', '0.5.5', '0.5.6', '0.5.7'))
      OR (name = '@squawk/airway-data' AND version IN ('0.5.4', '0.5.5', '0.5.6', '0.5.7', '0.5.8'))
      OR (name = '@squawk/airways' AND version IN ('0.4.2', '0.4.3', '0.4.4', '0.4.5', '0.4.6'))
      OR (name = '@squawk/fix-data' AND version IN ('0.6.4', '0.6.5', '0.6.6', '0.6.7', '0.6.8'))
      OR (name = '@squawk/fixes' AND version IN ('0.3.2', '0.3.3', '0.3.4', '0.3.5', '0.3.6'))
      OR (name = '@squawk/flight-math' AND version IN ('0.5.4', '0.5.5', '0.5.6', '0.5.7', '0.5.8'))
      OR (name = '@squawk/flightplan' AND version IN ('0.5.2', '0.5.3', '0.5.4', '0.5.5', '0.5.6'))
      OR (name = '@squawk/geo' AND version IN ('0.4.4', '0.4.5', '0.4.6', '0.4.7', '0.4.8'))
      OR (name = '@squawk/icao-registry' AND version IN ('0.5.2', '0.5.3', '0.5.4', '0.5.5', '0.5.6'))
      OR (name = '@squawk/icao-registry-data' AND version IN ('0.8.4', '0.8.5', '0.8.6', '0.8.7', '0.8.8'))
      OR (name = '@squawk/mcp' AND version IN ('0.9.1', '0.9.2', '0.9.3', '0.9.4', '0.9.5'))
      OR (name = '@squawk/navaid-data' AND version IN ('0.6.4', '0.6.5', '0.6.6', '0.6.7', '0.6.8'))
      OR (name = '@squawk/navaids' AND version IN ('0.4.2', '0.4.3', '0.4.4', '0.4.5', '0.4.6'))
      OR (name = '@squawk/notams' AND version IN ('0.3.10', '0.3.6', '0.3.7', '0.3.8', '0.3.9'))
      OR (name = '@squawk/procedure-data' AND version IN ('0.7.3', '0.7.4', '0.7.5', '0.7.6', '0.7.7'))
      OR (name = '@squawk/procedures' AND version IN ('0.5.2', '0.5.3', '0.5.4', '0.5.5', '0.5.6'))
      OR (name = '@squawk/types' AND version IN ('0.8.1', '0.8.2', '0.8.3', '0.8.4', '0.8.5'))
      OR (name = '@squawk/units' AND version IN ('0.4.3', '0.4.4', '0.4.5', '0.4.6', '0.4.7'))
      OR (name = '@squawk/weather' AND version IN ('0.5.10', '0.5.6', '0.5.7', '0.5.8', '0.5.9'))
      OR (name = '@supersurkhet/cli' AND version IN ('0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.0.7'))
      OR (name = '@supersurkhet/sdk' AND version IN ('0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.0.7'))
      OR (name = '@tallyui/components' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/connector-medusa' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/connector-shopify' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/connector-vendure' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/connector-woocommerce' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/core' AND version IN ('0.2.1', '0.2.2', '0.2.3'))
      OR (name = '@tallyui/database' AND version IN ('1.0.1', '1.0.2', '1.0.3'))
      OR (name = '@tallyui/pos' AND version IN ('0.1.1', '0.1.2', '0.1.3'))
      OR (name = '@tallyui/storage-sqlite' AND version IN ('0.2.1', '0.2.2', '0.2.3'))
      OR (name = '@tallyui/theme' AND version IN ('0.2.1', '0.2.2', '0.2.3'))
      OR (name = '@tanstack/arktype-adapter' AND version IN ('1.166.12', '1.166.15'))
      OR (name = '@tanstack/eslint-plugin-router' AND version IN ('1.161.12', '1.161.9'))
      OR (name = '@tanstack/eslint-plugin-start' AND version IN ('0.0.4', '0.0.7'))
      OR (name = '@tanstack/history' AND version IN ('1.161.12', '1.161.9'))
      OR (name = '@tanstack/nitro-v2-vite-plugin' AND version IN ('1.154.12', '1.154.15'))
      OR (name = '@tanstack/react-router' AND version IN ('1.169.5', '1.169.8'))
      OR (name = '@tanstack/react-router-devtools' AND version IN ('1.166.16', '1.166.19'))
      OR (name = '@tanstack/react-router-ssr-query' AND version IN ('1.166.15', '1.166.18'))
      OR (name = '@tanstack/react-start' AND version IN ('1.167.68', '1.167.71'))
      OR (name = '@tanstack/react-start-client' AND version IN ('1.166.51', '1.166.54'))
      OR (name = '@tanstack/react-start-rsc' AND version IN ('0.0.47', '0.0.50'))
      OR (name = '@tanstack/react-start-server' AND version IN ('1.166.55', '1.166.58'))
      OR (name = '@tanstack/router-cli' AND version IN ('1.166.46', '1.166.49'))
      OR (name = '@tanstack/router-core' AND version IN ('1.169.5', '1.169.8'))
      OR (name = '@tanstack/router-devtools' AND version IN ('1.166.16', '1.166.19'))
      OR (name = '@tanstack/router-devtools-core' AND version IN ('1.167.6', '1.167.9'))
      OR (name = '@tanstack/router-generator' AND version IN ('1.166.45', '1.166.48'))
      OR (name = '@tanstack/router-plugin' AND version IN ('1.167.38', '1.167.41'))
      OR (name = '@tanstack/router-ssr-query-core' AND version IN ('1.168.3', '1.168.6'))
      OR (name = '@tanstack/router-utils' AND version IN ('1.161.11', '1.161.14'))
      OR (name = '@tanstack/router-vite-plugin' AND version IN ('1.166.53', '1.166.56'))
      OR (name = '@tanstack/solid-router' AND version IN ('1.169.5', '1.169.8'))
      OR (name = '@tanstack/solid-router-devtools' AND version IN ('1.166.16', '1.166.19'))
      OR (name = '@tanstack/solid-router-ssr-query' AND version IN ('1.166.15', '1.166.18'))
      OR (name = '@tanstack/solid-start' AND version IN ('1.167.65', '1.167.68'))
      OR (name = '@tanstack/solid-start-client' AND version IN ('1.166.50', '1.166.53'))
      OR (name = '@tanstack/solid-start-server' AND version IN ('1.166.54', '1.166.57'))
      OR (name = '@tanstack/start-client-core' AND version IN ('1.168.5', '1.168.8'))
      OR (name = '@tanstack/start-fn-stubs' AND version IN ('1.161.12', '1.161.9'))
      OR (name = '@tanstack/start-plugin-core' AND version IN ('1.169.23', '1.169.26'))
      OR (name = '@tanstack/start-server-core' AND version IN ('1.167.33', '1.167.36'))
      OR (name = '@tanstack/start-static-server-functions' AND version IN ('1.166.44', '1.166.47'))
      OR (name = '@tanstack/start-storage-context' AND version IN ('1.166.38', '1.166.41'))
      OR (name = '@tanstack/valibot-adapter' AND version IN ('1.166.12', '1.166.15'))
      OR (name = '@tanstack/virtual-file-routes' AND version IN ('1.161.10', '1.161.13'))
      OR (name = '@tanstack/vue-router' AND version IN ('1.169.5', '1.169.8'))
      OR (name = '@tanstack/vue-router-devtools' AND version IN ('1.166.16', '1.166.19'))
      OR (name = '@tanstack/vue-router-ssr-query' AND version IN ('1.166.15', '1.166.18'))
      OR (name = '@tanstack/vue-start' AND version IN ('1.167.61', '1.167.64'))
      OR (name = '@tanstack/vue-start-client' AND version IN ('1.166.46', '1.166.49'))
      OR (name = '@tanstack/vue-start-server' AND version IN ('1.166.50', '1.166.53'))
      OR (name = '@tanstack/zod-adapter' AND version IN ('1.166.12', '1.166.15'))
      OR (name = '@taskflow-corp/cli' AND version IN ('0.1.24', '0.1.25', '0.1.26', '0.1.27', '0.1.28', '0.1.29'))
      OR (name = '@tolka/cli' AND version IN ('1.0.2', '1.0.3', '1.0.4', '1.0.5', '1.0.6'))
      OR (name = '@uipath/access-policy-sdk' AND version = '0.3.1')
      OR (name = '@uipath/access-policy-tool' AND version = '0.3.1')
      OR (name = '@uipath/admin-tool' AND version = '0.1.1')
      OR (name = '@uipath/agent-sdk' AND version = '1.0.2')
      OR (name = '@uipath/agent-tool' AND version = '1.0.1')
      OR (name = '@uipath/agent.sdk' AND version = '0.0.18')
      OR (name = '@uipath/aops-policy-tool' AND version = '0.3.1')
      OR (name = '@uipath/ap-chat' AND version = '1.5.7')
      OR (name = '@uipath/api-workflow-tool' AND version = '1.0.1')
      OR (name = '@uipath/apollo-core' AND version = '5.9.2')
      OR (name = '@uipath/apollo-react' AND version = '4.24.5')
      OR (name = '@uipath/apollo-wind' AND version = '2.16.2')
      OR (name = '@uipath/auth' AND version = '1.0.1')
      OR (name = '@uipath/case-tool' AND version = '1.0.1')
      OR (name = '@uipath/cli' AND version = '1.0.1')
      OR (name = '@uipath/codedagent-tool' AND version = '1.0.1')
      OR (name = '@uipath/codedagents-tool' AND version = '0.1.12')
      OR (name = '@uipath/codedapp-tool' AND version = '1.0.1')
      OR (name = '@uipath/common' AND version = '1.0.1')
      OR (name = '@uipath/context-grounding-tool' AND version = '0.1.1')
      OR (name = '@uipath/data-fabric-tool' AND version = '1.0.2')
      OR (name = '@uipath/docsai-tool' AND version = '1.0.1')
      OR (name = '@uipath/filesystem' AND version = '1.0.1')
      OR (name = '@uipath/flow-tool' AND version = '1.0.2')
      OR (name = '@uipath/functions-tool' AND version = '1.0.1')
      OR (name = '@uipath/gov-tool' AND version = '0.3.1')
      OR (name = '@uipath/identity-tool' AND version = '0.1.1')
      OR (name = '@uipath/insights-sdk' AND version = '1.0.1')
      OR (name = '@uipath/insights-tool' AND version = '1.0.1')
      OR (name = '@uipath/integrationservice-sdk' AND version = '1.0.2')
      OR (name = '@uipath/integrationservice-tool' AND version = '1.0.2')
      OR (name = '@uipath/llmgw-tool' AND version = '1.0.1')
      OR (name = '@uipath/maestro-sdk' AND version = '1.0.1')
      OR (name = '@uipath/maestro-tool' AND version = '1.0.1')
      OR (name = '@uipath/orchestrator-tool' AND version = '1.0.1')
      OR (name = '@uipath/packager-tool-apiworkflow' AND version = '0.0.19')
      OR (name = '@uipath/packager-tool-bpmn' AND version = '0.0.9')
      OR (name = '@uipath/packager-tool-case' AND version = '0.0.9')
      OR (name = '@uipath/packager-tool-connector' AND version = '0.0.19')
      OR (name = '@uipath/packager-tool-flow' AND version = '0.0.19')
      OR (name = '@uipath/packager-tool-functions' AND version = '0.1.1')
      OR (name = '@uipath/packager-tool-webapp' AND version = '1.0.6')
      OR (name = '@uipath/packager-tool-workflowcompiler' AND version = '0.0.16')
      OR (name = '@uipath/packager-tool-workflowcompiler-browser' AND version = '0.0.34')
      OR (name = '@uipath/platform-tool' AND version = '1.0.1')
      OR (name = '@uipath/project-packager' AND version = '1.1.16')
      OR (name = '@uipath/resource-tool' AND version = '1.0.1')
      OR (name = '@uipath/resourcecatalog-tool' AND version = '0.1.1')
      OR (name = '@uipath/resources-tool' AND version = '0.1.11')
      OR (name = '@uipath/robot' AND version = '1.3.4')
      OR (name = '@uipath/rpa-legacy-tool' AND version = '1.0.1')
      OR (name = '@uipath/rpa-tool' AND version = '0.9.5')
      OR (name = '@uipath/solution-packager' AND version = '0.0.35')
      OR (name = '@uipath/solution-tool' AND version = '1.0.1')
      OR (name = '@uipath/solutionpackager-sdk' AND version = '1.0.11')
      OR (name = '@uipath/solutionpackager-tool-core' AND version = '0.0.34')
      OR (name = '@uipath/tasks-tool' AND version = '1.0.1')
      OR (name = '@uipath/telemetry' AND version = '0.0.7')
      OR (name = '@uipath/test-manager-tool' AND version = '1.0.2')
      OR (name = '@uipath/tool-workflowcompiler' AND version = '0.0.12')
      OR (name = '@uipath/traces-tool' AND version = '1.0.1')
      OR (name = '@uipath/ui-widgets-multi-file-upload' AND version = '1.0.1')
      OR (name = '@uipath/uipath-python-bridge' AND version = '1.0.1')
      OR (name = '@uipath/vertical-solutions-tool' AND version = '1.0.1')
      OR (name = '@uipath/vss' AND version = '0.1.6')
      OR (name = '@uipath/widget.sdk' AND version = '1.2.3')
      OR (name = 'agentwork-cli' AND version IN ('0.1.4', '0.1.5'))
      OR (name = 'cmux-agent-mcp' AND version IN ('0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7', '0.1.8'))
      OR (name = 'cross-stitch' AND version IN ('1.1.3', '1.1.4', '1.1.5', '1.1.6', '1.1.7'))
      OR (name = 'git-branch-selector' AND version IN ('1.3.3', '1.3.4', '1.3.5', '1.3.6', '1.3.7'))
      OR (name = 'git-git-git' AND version IN ('1.0.10', '1.0.11', '1.0.12', '1.0.8', '1.0.9'))
      OR (name = 'intercom-client' AND version = '7.0.4')
      OR (name = 'mbt' AND version = '1.2.48')
      OR (name = 'ml-toolkit-ts' AND version IN ('1.0.4', '1.0.5'))
      OR (name = 'nextmove-mcp' AND version IN ('0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7'))
      OR (name = 'safe-action' AND version IN ('0.8.3', '0.8.4'))
      OR (name = 'ts-dna' AND version IN ('3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5'))
      OR (name = 'wot-api' AND version IN ('0.8.1', '0.8.2', '0.8.3', '0.8.4'))
   OR name = '@tanstack/setup'   -- forged package, never legit at any version

UNION ALL

-- CRITICAL: dead-man's-switch LaunchAgent plist on disk.
-- Revoking GitHub creds before disabling this triggers `rm -rf ~/`.
SELECT 'CRITICAL_persistence_launchagent_plist' AS indicator, path FROM file
WHERE path LIKE '/Users/%/Library/LaunchAgents/com.user.gh-token-monitor.plist'

UNION ALL

-- CRITICAL: launchd table has loaded the malicious agent
SELECT 'CRITICAL_persistence_launchd_loaded' AS indicator,
       COALESCE(path, label) AS path
FROM launchd
WHERE label LIKE '%gh-token-monitor%'
   OR (path IS NOT NULL AND path LIKE '%gh-token-monitor%')
   OR (program IS NOT NULL AND program LIKE '%gh-token-monitor%')
   OR (program_arguments IS NOT NULL AND program_arguments LIKE '%gh-token-monitor%')

UNION ALL

-- CRITICAL: router_init.js (primary payload) in project-local or global node_modules
SELECT 'CRITICAL_payload_router_init_js' AS indicator, path FROM file
WHERE path LIKE '/Users/%/%%/node_modules/%/router_init.js'
   OR path LIKE '/Users/%/%%/node_modules/@%/%/router_init.js'
   OR path LIKE '/usr/local/lib/node_modules/%/router_init.js'
   OR path LIKE '/usr/local/lib/node_modules/@%/%/router_init.js'
   OR path LIKE '/opt/homebrew/lib/node_modules/%/router_init.js'
   OR path LIKE '/opt/homebrew/lib/node_modules/@%/%/router_init.js'

UNION ALL

-- CRITICAL: tanstack_runner.js (secondary payload from orphan commit 79ac49ee)
SELECT 'CRITICAL_payload_tanstack_runner_js' AS indicator, path FROM file
WHERE path LIKE '/Users/%/%%/node_modules/@tanstack/setup/tanstack_runner.js'
   OR path LIKE '/usr/local/lib/node_modules/@tanstack/setup/tanstack_runner.js'
   OR path LIKE '/opt/homebrew/lib/node_modules/@tanstack/setup/tanstack_runner.js'

UNION ALL

-- CRITICAL: payload actively running right now
SELECT 'CRITICAL_active_payload_process' AS indicator,
       'pid=' || pid || ' name=' || name || ' cmdline=' || cmdline AS path
FROM processes
WHERE cmdline LIKE '%router_init.js%'
   OR cmdline LIKE '%router_runtime.js%'
   OR cmdline LIKE '%tanstack_runner.js%'

UNION ALL

-- HIGH: editor-hook persistence (re-compromise on every project open)
SELECT 'HIGH_persistence_editor_hook' AS indicator, path FROM file
WHERE path LIKE '/Users/%/%%/.claude/router_runtime.js'
   OR path LIKE '/Users/%/%%/.claude/setup.mjs'
   OR path LIKE '/Users/%/%%/.vscode/setup.mjs';
