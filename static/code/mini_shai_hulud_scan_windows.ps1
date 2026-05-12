# ============================================================================
# Mini Shai-Hulud TanStack worm scanner (POWERShell VERSION - DEEP SCAN)
# CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx
#
# For Fleet deployment on Windows - runs FULL DEEP SCAN by default (~5min).
# Comprehensive detection across entire Windows filesystem.
#
# Usage in Fleet:
#   - Script runs automatically, no arguments needed
#   - Full filesystem scan with campaign marker detection
#   - Timeout: 300 seconds (5 minutes)
#
# Exit codes:
#   0 = CLEAN  (no indicators)
#   1 = EXPOSED  (vulnerable package version installed but no execution evidence)
#   2 = HIGH  (editor-hook persistence found)
#   3 = CRITICAL  (payload file / system persistence found - likely compromised)
# ============================================================================

[CmdletBinding()]
param()

# ----------------------------- Configuration --------------------------------
$ErrorActionPreference = 'Continue'
$MODE = "deep"
$TIMEOUT_SEC = 300
$START_TIME = Get-Date

# IOC table
$ROUTER_INIT_SHA256 = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
$TANSTACK_RUNNER_SHA256 = "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
$DEAD_DROP_AUTHOR_EMAIL = "claude@users.noreply.github.com"
$VOICPRODUCOES_AUTHOR = "voicproducoes"  # Compromised GitHub account
$TANSTACK_SETUP_COMMIT = "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
$CAMPAIGN_SALT = "svksjrhjkcejg"
$CAMPAIGN_STRING = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"

# Compromised package-version pins (from Socket.dev blog + TanStack postmortem)
$COMPROMISED_PKGS = @(
    "@beproduct/nestjs-auth@0.1.10",
    "@beproduct/nestjs-auth@0.1.11",
    "@beproduct/nestjs-auth@0.1.12",
    "@beproduct/nestjs-auth@0.1.13",
    "@beproduct/nestjs-auth@0.1.14",
    "@beproduct/nestjs-auth@0.1.15",
    "@beproduct/nestjs-auth@0.1.16",
    "@beproduct/nestjs-auth@0.1.17",
    "@beproduct/nestjs-auth@0.1.18",
    "@beproduct/nestjs-auth@0.1.19",
    "@beproduct/nestjs-auth@0.1.2",
    "@beproduct/nestjs-auth@0.1.3",
    "@beproduct/nestjs-auth@0.1.4",
    "@beproduct/nestjs-auth@0.1.5",
    "@beproduct/nestjs-auth@0.1.6",
    "@beproduct/nestjs-auth@0.1.7",
    "@beproduct/nestjs-auth@0.1.8",
    "@beproduct/nestjs-auth@0.1.9",
    "@cap-js/db-service@2.10.1",
    "@cap-js/postgres@2.2.2",
    "@cap-js/sqlite@2.2.2",
    "@dirigible-ai/sdk@0.6.2",
    "@dirigible-ai/sdk@0.6.3",
    "@draftauth/client@0.2.1",
    "@draftauth/client@0.2.2",
    "@draftauth/core@0.13.1",
    "@draftauth/core@0.13.2",
    "@draftlab/auth@0.24.1",
    "@draftlab/auth@0.24.2",
    "@draftlab/auth-router@0.5.1",
    "@draftlab/auth-router@0.5.2",
    "@draftlab/db@0.16.1",
    "@draftlab/db@0.16.2",
    "@mesadev/rest@0.28.3",
    "@mesadev/saguaro@0.4.22",
    "@mesadev/sdk@0.28.3",
    "@mistralai/mistralai@2.2.2",
    "@mistralai/mistralai@2.2.3",
    "@mistralai/mistralai@2.2.4",
    "@mistralai/mistralai-azure@1.7.1",
    "@mistralai/mistralai-azure@1.7.2",
    "@mistralai/mistralai-azure@1.7.3",
    "@mistralai/mistralai-gcp@1.7.1",
    "@mistralai/mistralai-gcp@1.7.2",
    "@mistralai/mistralai-gcp@1.7.3",
    "@ml-toolkit-ts/preprocessing@1.0.2",
    "@ml-toolkit-ts/preprocessing@1.0.3",
    "@ml-toolkit-ts/xgboost@1.0.3",
    "@ml-toolkit-ts/xgboost@1.0.4",
    "@opensearch-project/opensearch@3.6.2",
    "@squawk/airport-data@0.7.4",
    "@squawk/airport-data@0.7.5",
    "@squawk/airport-data@0.7.6",
    "@squawk/airport-data@0.7.7",
    "@squawk/airport-data@0.7.8",
    "@squawk/airports@0.6.2",
    "@squawk/airports@0.6.3",
    "@squawk/airports@0.6.4",
    "@squawk/airports@0.6.5",
    "@squawk/airports@0.6.6",
    "@squawk/airspace@0.8.1",
    "@squawk/airspace@0.8.2",
    "@squawk/airspace@0.8.3",
    "@squawk/airspace@0.8.4",
    "@squawk/airspace@0.8.5",
    "@squawk/airspace-data@0.5.3",
    "@squawk/airspace-data@0.5.4",
    "@squawk/airspace-data@0.5.5",
    "@squawk/airspace-data@0.5.6",
    "@squawk/airspace-data@0.5.7",
    "@squawk/airway-data@0.5.4",
    "@squawk/airway-data@0.5.5",
    "@squawk/airway-data@0.5.6",
    "@squawk/airway-data@0.5.7",
    "@squawk/airway-data@0.5.8",
    "@squawk/airways@0.4.2",
    "@squawk/airways@0.4.3",
    "@squawk/airways@0.4.4",
    "@squawk/airways@0.4.5",
    "@squawk/airways@0.4.6",
    "@squawk/fix-data@0.6.4",
    "@squawk/fix-data@0.6.5",
    "@squawk/fix-data@0.6.6",
    "@squawk/fix-data@0.6.7",
    "@squawk/fix-data@0.6.8",
    "@squawk/fixes@0.3.2",
    "@squawk/fixes@0.3.3",
    "@squawk/fixes@0.3.4",
    "@squawk/fixes@0.3.5",
    "@squawk/fixes@0.3.6",
    "@squawk/flight-math@0.5.4",
    "@squawk/flight-math@0.5.5",
    "@squawk/flight-math@0.5.6",
    "@squawk/flight-math@0.5.7",
    "@squawk/flight-math@0.5.8",
    "@squawk/flightplan@0.5.2",
    "@squawk/flightplan@0.5.3",
    "@squawk/flightplan@0.5.4",
    "@squawk/flightplan@0.5.5",
    "@squawk/flightplan@0.5.6",
    "@squawk/geo@0.4.4",
    "@squawk/geo@0.4.5",
    "@squawk/geo@0.4.6",
    "@squawk/geo@0.4.7",
    "@squawk/geo@0.4.8",
    "@squawk/icao-registry@0.5.2",
    "@squawk/icao-registry@0.5.3",
    "@squawk/icao-registry@0.5.4",
    "@squawk/icao-registry@0.5.5",
    "@squawk/icao-registry@0.5.6",
    "@squawk/icao-registry-data@0.8.4",
    "@squawk/icao-registry-data@0.8.5",
    "@squawk/icao-registry-data@0.8.6",
    "@squawk/icao-registry-data@0.8.7",
    "@squawk/icao-registry-data@0.8.8",
    "@squawk/mcp@0.9.1",
    "@squawk/mcp@0.9.2",
    "@squawk/mcp@0.9.3",
    "@squawk/mcp@0.9.4",
    "@squawk/mcp@0.9.5",
    "@squawk/navaid-data@0.6.4",
    "@squawk/navaid-data@0.6.5",
    "@squawk/navaid-data@0.6.6",
    "@squawk/navaid-data@0.6.7",
    "@squawk/navaid-data@0.6.8",
    "@squawk/navaids@0.4.2",
    "@squawk/navaids@0.4.3",
    "@squawk/navaids@0.4.4",
    "@squawk/navaids@0.4.5",
    "@squawk/navaids@0.4.6",
    "@squawk/notams@0.3.10",
    "@squawk/notams@0.3.6",
    "@squawk/notams@0.3.7",
    "@squawk/notams@0.3.8",
    "@squawk/notams@0.3.9",
    "@squawk/procedure-data@0.7.3",
    "@squawk/procedure-data@0.7.4",
    "@squawk/procedure-data@0.7.5",
    "@squawk/procedure-data@0.7.6",
    "@squawk/procedure-data@0.7.7",
    "@squawk/procedures@0.5.2",
    "@squawk/procedures@0.5.3",
    "@squawk/procedures@0.5.4",
    "@squawk/procedures@0.5.5",
    "@squawk/procedures@0.5.6",
    "@squawk/types@0.8.1",
    "@squawk/types@0.8.2",
    "@squawk/types@0.8.3",
    "@squawk/types@0.8.4",
    "@squawk/types@0.8.5",
    "@squawk/units@0.4.3",
    "@squawk/units@0.4.4",
    "@squawk/units@0.4.5",
    "@squawk/units@0.4.6",
    "@squawk/units@0.4.7",
    "@squawk/weather@0.5.10",
    "@squawk/weather@0.5.6",
    "@squawk/weather@0.5.7",
    "@squawk/weather@0.5.8",
    "@squawk/weather@0.5.9",
    "@supersurkhet/cli@0.0.2",
    "@supersurkhet/cli@0.0.3",
    "@supersurkhet/cli@0.0.4",
    "@supersurkhet/cli@0.0.5",
    "@supersurkhet/cli@0.0.6",
    "@supersurkhet/cli@0.0.7",
    "@supersurkhet/sdk@0.0.2",
    "@supersurkhet/sdk@0.0.3",
    "@supersurkhet/sdk@0.0.4",
    "@supersurkhet/sdk@0.0.5",
    "@supersurkhet/sdk@0.0.6",
    "@supersurkhet/sdk@0.0.7",
    "@tallyui/components@1.0.1",
    "@tallyui/components@1.0.2",
    "@tallyui/components@1.0.3",
    "@tallyui/connector-medusa@1.0.1",
    "@tallyui/connector-medusa@1.0.2",
    "@tallyui/connector-medusa@1.0.3",
    "@tallyui/connector-shopify@1.0.1",
    "@tallyui/connector-shopify@1.0.2",
    "@tallyui/connector-shopify@1.0.3",
    "@tallyui/connector-vendure@1.0.1",
    "@tallyui/connector-vendure@1.0.2",
    "@tallyui/connector-vendure@1.0.3",
    "@tallyui/connector-woocommerce@1.0.1",
    "@tallyui/connector-woocommerce@1.0.2",
    "@tallyui/connector-woocommerce@1.0.3",
    "@tallyui/core@0.2.1",
    "@tallyui/core@0.2.2",
    "@tallyui/core@0.2.3",
    "@tallyui/database@1.0.1",
    "@tallyui/database@1.0.2",
    "@tallyui/database@1.0.3",
    "@tallyui/pos@0.1.1",
    "@tallyui/pos@0.1.2",
    "@tallyui/pos@0.1.3",
    "@tallyui/storage-sqlite@0.2.1",
    "@tallyui/storage-sqlite@0.2.2",
    "@tallyui/storage-sqlite@0.2.3",
    "@tallyui/theme@0.2.1",
    "@tallyui/theme@0.2.2",
    "@tallyui/theme@0.2.3",
    "@tanstack/arktype-adapter@1.166.12",
    "@tanstack/arktype-adapter@1.166.15",
    "@tanstack/eslint-plugin-router@1.161.12",
    "@tanstack/eslint-plugin-router@1.161.9",
    "@tanstack/eslint-plugin-start@0.0.4",
    "@tanstack/eslint-plugin-start@0.0.7",
    "@tanstack/history@1.161.12",
    "@tanstack/history@1.161.9",
    "@tanstack/nitro-v2-vite-plugin@1.154.12",
    "@tanstack/nitro-v2-vite-plugin@1.154.15",
    "@tanstack/react-router@1.169.5",
    "@tanstack/react-router@1.169.8",
    "@tanstack/react-router-devtools@1.166.16",
    "@tanstack/react-router-devtools@1.166.19",
    "@tanstack/react-router-ssr-query@1.166.15",
    "@tanstack/react-router-ssr-query@1.166.18",
    "@tanstack/react-start@1.167.68",
    "@tanstack/react-start@1.167.71",
    "@tanstack/react-start-client@1.166.51",
    "@tanstack/react-start-client@1.166.54",
    "@tanstack/react-start-rsc@0.0.47",
    "@tanstack/react-start-rsc@0.0.50",
    "@tanstack/react-start-server@1.166.55",
    "@tanstack/react-start-server@1.166.58",
    "@tanstack/router-cli@1.166.46",
    "@tanstack/router-cli@1.166.49",
    "@tanstack/router-core@1.169.5",
    "@tanstack/router-core@1.169.8",
    "@tanstack/router-devtools@1.166.16",
    "@tanstack/router-devtools@1.166.19",
    "@tanstack/router-devtools-core@1.167.6",
    "@tanstack/router-devtools-core@1.167.9",
    "@tanstack/router-generator@1.166.45",
    "@tanstack/router-generator@1.166.48",
    "@tanstack/router-plugin@1.167.38",
    "@tanstack/router-plugin@1.167.41",
    "@tanstack/router-ssr-query-core@1.168.3",
    "@tanstack/router-ssr-query-core@1.168.6",
    "@tanstack/router-utils@1.161.11",
    "@tanstack/router-utils@1.161.14",
    "@tanstack/router-vite-plugin@1.166.53",
    "@tanstack/router-vite-plugin@1.166.56",
    "@tanstack/solid-router@1.169.5",
    "@tanstack/solid-router@1.169.8",
    "@tanstack/solid-router-devtools@1.166.16",
    "@tanstack/solid-router-devtools@1.166.19",
    "@tanstack/solid-router-ssr-query@1.166.15",
    "@tanstack/solid-router-ssr-query@1.166.18",
    "@tanstack/solid-start@1.167.65",
    "@tanstack/solid-start@1.167.68",
    "@tanstack/solid-start-client@1.166.50",
    "@tanstack/solid-start-client@1.166.53",
    "@tanstack/solid-start-server@1.166.54",
    "@tanstack/solid-start-server@1.166.57",
    "@tanstack/start-client-core@1.168.5",
    "@tanstack/start-client-core@1.168.8",
    "@tanstack/start-fn-stubs@1.161.12",
    "@tanstack/start-fn-stubs@1.161.9",
    "@tanstack/start-plugin-core@1.169.23",
    "@tanstack/start-plugin-core@1.169.26",
    "@tanstack/start-server-core@1.167.33",
    "@tanstack/start-server-core@1.167.36",
    "@tanstack/start-static-server-functions@1.166.44",
    "@tanstack/start-static-server-functions@1.166.47",
    "@tanstack/start-storage-context@1.166.38",
    "@tanstack/start-storage-context@1.166.41",
    "@tanstack/valibot-adapter@1.166.12",
    "@tanstack/valibot-adapter@1.166.15",
    "@tanstack/virtual-file-routes@1.161.10",
    "@tanstack/virtual-file-routes@1.161.13",
    "@tanstack/vue-router@1.169.5",
    "@tanstack/vue-router@1.169.8",
    "@tanstack/vue-router-devtools@1.166.16",
    "@tanstack/vue-router-devtools@1.166.19",
    "@tanstack/vue-router-ssr-query@1.166.15",
    "@tanstack/vue-router-ssr-query@1.166.18",
    "@tanstack/vue-start@1.167.61",
    "@tanstack/vue-start@1.167.64",
    "@tanstack/vue-start-client@1.166.46",
    "@tanstack/vue-start-client@1.166.49",
    "@tanstack/vue-start-server@1.166.50",
    "@tanstack/vue-start-server@1.166.53",
    "@tanstack/zod-adapter@1.166.12",
    "@tanstack/zod-adapter@1.166.15",
    "@taskflow-corp/cli@0.1.24",
    "@taskflow-corp/cli@0.1.25",
    "@taskflow-corp/cli@0.1.26",
    "@taskflow-corp/cli@0.1.27",
    "@taskflow-corp/cli@0.1.28",
    "@taskflow-corp/cli@0.1.29",
    "@tolka/cli@1.0.2",
    "@tolka/cli@1.0.3",
    "@tolka/cli@1.0.4",
    "@tolka/cli@1.0.5",
    "@tolka/cli@1.0.6",
    "@uipath/access-policy-sdk@0.3.1",
    "@uipath/access-policy-tool@0.3.1",
    "@uipath/admin-tool@0.1.1",
    "@uipath/agent-sdk@1.0.2",
    "@uipath/agent-tool@1.0.1",
    "@uipath/agent.sdk@0.0.18",
    "@uipath/aops-policy-tool@0.3.1",
    "@uipath/ap-chat@1.5.7",
    "@uipath/api-workflow-tool@1.0.1",
    "@uipath/apollo-core@5.9.2",
    "@uipath/apollo-react@4.24.5",
    "@uipath/apollo-wind@2.16.2",
    "@uipath/auth@1.0.1",
    "@uipath/case-tool@1.0.1",
    "@uipath/cli@1.0.1",
    "@uipath/codedagent-tool@1.0.1",
    "@uipath/codedagents-tool@0.1.12",
    "@uipath/codedapp-tool@1.0.1",
    "@uipath/common@1.0.1",
    "@uipath/context-grounding-tool@0.1.1",
    "@uipath/data-fabric-tool@1.0.2",
    "@uipath/docsai-tool@1.0.1",
    "@uipath/filesystem@1.0.1",
    "@uipath/flow-tool@1.0.2",
    "@uipath/functions-tool@1.0.1",
    "@uipath/gov-tool@0.3.1",
    "@uipath/identity-tool@0.1.1",
    "@uipath/insights-sdk@1.0.1",
    "@uipath/insights-tool@1.0.1",
    "@uipath/integrationservice-sdk@1.0.2",
    "@uipath/integrationservice-tool@1.0.2",
    "@uipath/llmgw-tool@1.0.1",
    "@uipath/maestro-sdk@1.0.1",
    "@uipath/maestro-tool@1.0.1",
    "@uipath/orchestrator-tool@1.0.1",
    "@uipath/packager-tool-apiworkflow@0.0.19",
    "@uipath/packager-tool-bpmn@0.0.9",
    "@uipath/packager-tool-case@0.0.9",
    "@uipath/packager-tool-connector@0.0.19",
    "@uipath/packager-tool-flow@0.0.19",
    "@uipath/packager-tool-functions@0.1.1",
    "@uipath/packager-tool-webapp@1.0.6",
    "@uipath/packager-tool-workflowcompiler@0.0.16",
    "@uipath/packager-tool-workflowcompiler-browser@0.0.34",
    "@uipath/platform-tool@1.0.1",
    "@uipath/project-packager@1.1.16",
    "@uipath/resource-tool@1.0.1",
    "@uipath/resourcecatalog-tool@0.1.1",
    "@uipath/resources-tool@0.1.11",
    "@uipath/robot@1.3.4",
    "@uipath/rpa-legacy-tool@1.0.1",
    "@uipath/rpa-tool@0.9.5",
    "@uipath/solution-packager@0.0.35",
    "@uipath/solution-tool@1.0.1",
    "@uipath/solutionpackager-sdk@1.0.11",
    "@uipath/solutionpackager-tool-core@0.0.34",
    "@uipath/tasks-tool@1.0.1",
    "@uipath/telemetry@0.0.7",
    "@uipath/test-manager-tool@1.0.2",
    "@uipath/tool-workflowcompiler@0.0.12",
    "@uipath/traces-tool@1.0.1",
    "@uipath/ui-widgets-multi-file-upload@1.0.1",
    "@uipath/uipath-python-bridge@1.0.1",
    "@uipath/vertical-solutions-tool@1.0.1",
    "@uipath/vss@0.1.6",
    "@uipath/widget.sdk@1.2.3",
    "agentwork-cli@0.1.4",
    "agentwork-cli@0.1.5",
    "cmux-agent-mcp@0.1.3",
    "cmux-agent-mcp@0.1.4",
    "cmux-agent-mcp@0.1.5",
    "cmux-agent-mcp@0.1.6",
    "cmux-agent-mcp@0.1.7",
    "cmux-agent-mcp@0.1.8",
    "cross-stitch@1.1.3",
    "cross-stitch@1.1.4",
    "cross-stitch@1.1.5",
    "cross-stitch@1.1.6",
    "cross-stitch@1.1.7",
    "git-branch-selector@1.3.3",
    "git-branch-selector@1.3.4",
    "git-branch-selector@1.3.5",
    "git-branch-selector@1.3.6",
    "git-branch-selector@1.3.7",
    "git-git-git@1.0.10",
    "git-git-git@1.0.11",
    "git-git-git@1.0.12",
    "git-git-git@1.0.8",
    "git-git-git@1.0.9",
    "intercom-client@7.0.4",
    "mbt@1.2.48",
    "ml-toolkit-ts@1.0.4",
    "ml-toolkit-ts@1.0.5",
    "nextmove-mcp@0.1.3",
    "nextmove-mcp@0.1.4",
    "nextmove-mcp@0.1.5",
    "nextmove-mcp@0.1.6",
    "nextmove-mcp@0.1.7",
    "safe-action@0.8.3",
    "safe-action@0.8.4",
    "ts-dna@3.0.1",
    "ts-dna@3.0.2",
    "ts-dna@3.0.3",
    "ts-dna@3.0.4",
    "ts-dna@3.0.5",
    "wot-api@0.8.1",
    "wot-api@0.8.2",
    "wot-api@0.8.3",
    "wot-api@0.8.4"
)

# ----------------------------- Counters -------------------------------------
$CRITICAL = 0
$HIGH = 0
$EXPOSURE = 0

function Write-Critical {
    param([string]$Message)
    $script:CRITICAL++
    Write-Host "[CRITICAL] $Message" -ForegroundColor Red
}

function Write-High {
    param([string]$Message)
    $script:HIGH++
    Write-Host "[HIGH]     $Message" -ForegroundColor Yellow
}

function Write-Exposure {
    param([string]$Message)
    $script:EXPOSURE++
    Write-Host "[EXPOSED]  $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "    [OK] $Message" -ForegroundColor Green
}

# ----------------------------- Header ---------------------------------------
Write-Host "==============================================================="
Write-Host "  Mini Shai-Hulud TanStack worm scan [DEEP SCAN]"
Write-Host "  CVE-2026-45321 | GHSA-g7cv-rxg3-hmpx"
Write-Host "  host=$env:COMPUTERNAME  platform=windows  time=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
Write-Host "==============================================================="
Write-Host ""

# ----------------------------- Helper: timeout guard ------------------------
function Check-Timeout {
    $Elapsed = (New-TimeSpan -Start $START_TIME -End (Get-Date)).TotalSeconds
    if ($Elapsed -gt $TIMEOUT_SEC) {
        Write-Host "`n[TIMEOUT] Scan exceeded $TIMEOUT_SEC seconds, stopping" -ForegroundColor Red
        return $false
    }
    return $true
}

# ----------------------------- Phase 1: Windows persistence -----------------
function Phase1-Persistence {
    Write-Host "[*] Phase 1 - Windows persistence (Scheduled Tasks/Registry)"
    
    # Check Scheduled Tasks for malicious tasks
    Write-Host "    Scanning Scheduled Tasks..."
    try {
        # Actions is an array of CIM objects, NOT a string. We must iterate
        # each action and check its .Execute / .Arguments / .WorkingDirectory.
        # Avoid the generic "*router*" pattern - it matches many legit tasks.
        $MaliciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            if ($_.TaskName -like "*gh-token-monitor*") { return $true }
            foreach ($Action in @($_.Actions)) {
                $AllStr = "$($Action.Execute) $($Action.Arguments) $($Action.WorkingDirectory)"
                if ($AllStr -match "gh-token-monitor|getsession\.org|router_init|router_runtime|tanstack_runner") {
                    return $true
                }
            }
            return $false
        }

        foreach ($Task in $MaliciousTasks) {
            Write-Critical "Scheduled Task: $($Task.TaskName)"
        }

        if (@($MaliciousTasks).Count -eq 0) {
            Write-OK "no malicious Scheduled Tasks"
        }
    }
    catch {
        Write-Host "    [WARN] Could not scan Scheduled Tasks: $_" -ForegroundColor Gray
    }
    
    # Check Registry Run keys for persistence
    Write-Host "    Scanning Registry Run keys..."
    $RegistryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    $FoundRegistry = 0
    foreach ($RegPath in $RegistryPaths) {
        try {
            if (Test-Path $RegPath) {
                $Values = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
                foreach ($PropertyName in $Values.PSObject.Properties.Name) {
                    $Value = $Values.$PropertyName
                    if ($Value -match "gh-token-monitor|getsession\.org|router_init|router_runtime") {
                        Write-Critical "Registry Run key: $RegPath\$PropertyName = $Value"
                        $FoundRegistry = 1
                    }
                }
            }
        }
        catch {
            # Skip inaccessible registry keys
        }
    }
    
    if ($FoundRegistry -eq 0) {
        Write-OK "no malicious Registry entries"
    }
    
    # Check for malicious scripts in startup folders
    Write-Host "    Scanning Startup folders..."
    $StartupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($StartupPath in $StartupPaths) {
        try {
            if (Test-Path $StartupPath) {
                $StartupFiles = Get-ChildItem -Path $StartupPath -File -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -match "gh-token|router|setup\.mjs"
                }
                foreach ($File in $StartupFiles) {
                    Write-Critical "Startup file: $($File.FullName)"
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }
    
    Write-Host ""
}

# ----------------------------- Phase 2: payload file hunt -------------------
# Hunts BOTH payload filenames: router_init.js (primary) and
# tanstack_runner.js (secondary, from orphan commit 79ac49ee).
# Hash-verifies every match. Does NOT early-exit or truncate - full count
# is essential for forensics.
function Phase2-RouterInit {
    Write-Host "[*] Phase 2 - payload files (router_init.js + tanstack_runner.js)"

    $Count = 0
    $ShaCount = 0

    $SearchPaths = @(
        "$env:USERPROFILE",
        "C:\Users",
        "$env:APPDATA\npm\node_modules",
        "$env:PROGRAMFILES\nodejs\node_modules",
        "C:\Program Files\nodejs\node_modules"
    )

    function Hunt-Payload {
        param(
            [string]$BasePath,
            [string]$PayloadName,
            [string]$ExpectedSha
        )

        $LocalCount = 0
        $LocalShaCount = 0
        try {
            # No -First N truncation here - we need the full list for forensics
            $Files = Get-ChildItem -Path $BasePath -Recurse -File `
                       -Filter $PayloadName -ErrorAction SilentlyContinue -Depth 10
            foreach ($File in $Files) {
                $LocalCount++
                try {
                    $Hash = Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $FileHash = $Hash.Hash.ToLower()
                    if ($FileHash -eq $ExpectedSha) {
                        $LocalShaCount++
                        Write-Critical "$PayloadName (SHA256 MATCH): $($File.FullName)"
                    }
                    else {
                        # Filename match but hash differs - still campaign-specific
                        # filename, surface as critical with hash truncated for review.
                        Write-Critical "$PayloadName (filename match, sha256=$($FileHash.Substring(0,16))...): $($File.FullName)"
                    }
                }
                catch {
                    Write-Critical "$PayloadName (filename match, hash check failed): $($File.FullName)"
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
        return @{ Count = $LocalCount; ShaCount = $LocalShaCount }
    }

    Write-Host "    Scanning user directories and global npm..."
    foreach ($BasePath in $SearchPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        $r1 = Hunt-Payload -BasePath $BasePath -PayloadName "router_init.js"     -ExpectedSha $ROUTER_INIT_SHA256
        $r2 = Hunt-Payload -BasePath $BasePath -PayloadName "tanstack_runner.js" -ExpectedSha $TANSTACK_RUNNER_SHA256
        $Count    += $r1.Count    + $r2.Count
        $ShaCount += $r1.ShaCount + $r2.ShaCount
    }

    if ($Count -eq 0) {
        Write-OK "none found"
    }
    else {
        Write-Host "    Found $Count payload file(s), $ShaCount with confirmed-bad SHA256" -ForegroundColor Yellow
    }

    Write-Host ""
}

# ----------------------------- Phase 3: editor-hook persistence -------------
function Phase3-EditorHooks {
    Write-Host "[*] Phase 3 - editor hooks (.claude/.vscode)"
    
    $Count = 0
    
    # Check user profile for .claude and .vscode
    $UserPaths = @(
        "$env:USERPROFILE\.claude",
        "$env:USERPROFILE\.vscode"
    )
    
    foreach ($BasePath in $UserPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        
        try {
            $HookFiles = Get-ChildItem -Path $BasePath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match "router_runtime\.js|setup\.mjs"
            }
            
            foreach ($File in $HookFiles) {
                $Count++
                Write-High "editor hook: $($File.FullName)"
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }
    
    if ($Count -eq 0) {
        Write-OK "none found"
    }
    
    Write-Host ""
}

# ----------------------------- Phase 4: compromised npm packages ------------
# Per-npm-tree scan. Critical fix: scoped packages like @tanstack/react-router
# live at <root>\@tanstack\react-router\, NOT <root>\react-router\. The
# previous Split-Path -Leaf approach silently dropped the scope and matched
# nothing.
function Phase4-NpmPackages {
    Write-Host "[*] Phase 4 - compromised npm packages"

    $Count = 0

    $NpmPaths = @(
        "$env:USERPROFILE\AppData\Roaming\npm\node_modules",
        "$env:PROGRAMFILES\nodejs\node_modules",
        "$env:USERPROFILE\node_modules"
    )

    foreach ($NpmPath in $NpmPaths) {
        if (-not (Test-Path $NpmPath)) { continue }

        Write-Host "    Scanning $NpmPath..."

        # @tanstack/setup is the forged package - ANY version is critical.
        $SetupPath = Join-Path $NpmPath "@tanstack\setup"
        if (Test-Path $SetupPath) {
            $Count++
            Write-Critical "@tanstack/setup directory present (forged package, any version): $SetupPath"
        }

        try {
            foreach ($PkgVer in $COMPROMISED_PKGS) {
                $PkgName = $PkgVer.Split('@')[0]
                # Scoped packages contain a leading '@', so .Split('@') gives
                # ['', 'scope/name', 'version']; index 1 is what we want for name.
                if ($PkgVer.StartsWith('@')) {
                    $PkgName    = '@' + $PkgVer.Split('@')[1]
                    $PkgVersion = $PkgVer.Split('@')[2]
                } else {
                    $PkgName    = $PkgVer.Split('@')[0]
                    $PkgVersion = $PkgVer.Split('@')[1]
                }

                # Build correct path: $NpmPath\@scope\name OR $NpmPath\name
                if ($PkgName.StartsWith('@')) {
                    $Parts = $PkgName -split '/', 2
                    $PkgPath = Join-Path (Join-Path $NpmPath $Parts[0]) $Parts[1]
                } else {
                    $PkgPath = Join-Path $NpmPath $PkgName
                }

                if (Test-Path $PkgPath) {
                    $PackageJson = Join-Path $PkgPath "package.json"
                    if (Test-Path $PackageJson) {
                        try {
                            $PkgInfo = Get-Content $PackageJson -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            if ($PkgInfo.version -eq $PkgVersion) {
                                $Count++
                                Write-Exposure "$PkgVer installed: $PackageJson"
                            }
                        }
                        catch {
                            # Skip invalid package.json
                        }
                    }
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }

    if ($Count -eq 0) {
        Write-OK "no compromised versions found"
    }

    Write-Host ""
}

# ----------------------------- Phase 5: git dead-drop commits ---------------
function Phase5-GitCommits {
    Write-Host "[*] Phase 5 - git dead-drop commits"
    
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "    [SKIP] git not available" -ForegroundColor Gray
        return
    }
    
    $Count = 0
    
    # Search common git repo locations
    $GitSearchPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\source\repos",
        "$env:USERPROFILE\projects"
    )
    
    foreach ($BasePath in $GitSearchPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        
        Write-Host "    Scanning git repos in $BasePath..."
        
        try {
            $GitDirs = Get-ChildItem -Path $BasePath -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue -Depth 8 | Select-Object -First 30
            
            foreach ($GitDir in $GitDirs) {
                $RepoPath = $GitDir.FullName | Split-Path -Parent
                
                try {
                    # NOTE: -ErrorAction is a PowerShell common parameter and does
                    # NOT apply to external commands like git. Use 2>$null instead,
                    # otherwise git receives "-ErrorAction SilentlyContinue" as
                    # literal arguments and fails.
                    $Commits = & git -C $RepoPath log --all --author=$DEAD_DROP_AUTHOR_EMAIL --pretty='%h %s' 2>$null | Select-Object -First 10
                    
                    if ($Commits) {
                        $Count++
                        if ($Commits -match "chore: update dependencies|dependabout") {
                            Write-High "campaign commits (claude@) in: $RepoPath"
                        }
                        else {
                            Write-Host "    [INFO] Claude commits in $RepoPath (review manually):" -ForegroundColor Gray
                            $Commits | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
                        }
                    }
                    
                    # Check for voicproducoes (compromised account) commits
                    $VoicCommits = & git -C $RepoPath log --all --author=$VOICPRODUCOES_AUTHOR --pretty='%h %s' 2>$null | Select-Object -First 10
                    
                    if ($VoicCommits) {
                        $Count++
                        if ($VoicCommits -match "Mini Shai-Hulud|tanstack|router") {
                            Write-High "campaign commits (voicproducoes) in: $RepoPath"
                        }
                        else {
                            Write-Host "    [INFO] voicproducoes commits in $RepoPath (review manually):" -ForegroundColor Gray
                            $VoicCommits | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
                        }
                    }
                    
                    # Check for tanstack/setup commit reference in package files.
                    # Previous code used bash-style "**\*" glob which PowerShell
                    # does NOT expand - Select-String -Path saw a literal pattern
                    # and matched nothing. Now: enumerate via Get-ChildItem, then
                    # grep with Select-String. Narrow to package files to keep it
                    # fast and reduce false positives.
                    $TargetFiles = Get-ChildItem -Path $RepoPath -Recurse -File `
                                     -ErrorAction SilentlyContinue -Depth 4 |
                                   Where-Object { $_.Name -in @('package.json','package-lock.json','.gitmodules','yarn.lock','bun.lock','pnpm-lock.yaml') }
                    $SetupRefs = $TargetFiles | Select-String -Pattern $TANSTACK_SETUP_COMMIT -ErrorAction SilentlyContinue | Select-Object -First 5
                    if ($SetupRefs) {
                        Write-Critical "tanstack/setup commit reference found in: $RepoPath"
                    }
                    
                }
                catch {
                    # Skip repos with git errors
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }
    
    if ($Count -eq 0) {
        Write-OK "no campaign-pattern commits found"
    }
    
    Write-Host ""
}

# ----------------------------- Phase 6: campaign markers ---------------------
function Phase6-CampaignMarkers {
    Write-Host "[*] Phase 6 - campaign markers in package.json (deep scan)"
    
    $Count = 0
    
    # Search for package.json files
    $SearchPaths = @(
        "$env:USERPROFILE",
        "C:\Users"
    )
    
    foreach ($BasePath in $SearchPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        
        Write-Host "    Scanning package.json files in $BasePath..."
        
        try {
            $PackageJsonFiles = Get-ChildItem -Path $BasePath -Recurse -File -Filter "package.json" -ErrorAction SilentlyContinue -Depth 10 | Select-Object -First 100
            
            foreach ($File in $PackageJsonFiles) {
                if (-not (Check-Timeout)) { return }
                
                try {
                    $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
                    if ($Content -match $CAMPAIGN_SALT -or $Content -match $CAMPAIGN_STRING -or $Content -match $DEAD_DROP_AUTHOR_EMAIL) {
                        $Count++
                        Write-Critical "campaign marker: $($File.FullName)"
                    }
                    
                    # Check for tanstack/setup github reference with suspicious commit
                    if ($Content -match "github:tanstack/router.*$TANSTACK_SETUP_COMMIT") {
                        $Count++
                        Write-Critical "tanstack/setup malicious commit: $($File.FullName)"
                    }
                }
                catch {
                    # Skip unreadable files
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }
    
    if ($Count -eq 0) {
        Write-OK "no campaign markers found"
    }
    
    Write-Host ""
}

# ----------------------------- Phase 7: workflow injection ------------------
function Phase7-WorkflowInjection {
    Write-Host "[*] Phase 7 - injected GitHub workflows"
    
    $Count = 0
    
    $SearchPaths = @(
        "$env:USERPROFILE",
        "C:\Users"
    )
    
    foreach ($BasePath in $SearchPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        
        try {
            $WorkflowFiles = Get-ChildItem -Path $BasePath -Recurse -File -Filter "*.yml" -ErrorAction SilentlyContinue -Depth 10 | Where-Object {
                $_.FullName -match "\.github\\workflows\\"
            } | Select-Object -First 50
            
            foreach ($File in $WorkflowFiles) {
                if (-not (Check-Timeout)) { return }
                
                try {
                    $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
                    if ($Content -match "toJSON\(secrets\)|getsession\.org|masscan\.cloud|__DAEMONIZED|router_init") {
                        $Count++
                        Write-Critical "malicious workflow: $($File.FullName)"
                    }
                }
                catch {
                    # Skip unreadable files
                }
            }
        }
        catch {
            # Skip inaccessible paths
        }
    }
    
    if ($Count -eq 0) {
        Write-OK "no malicious workflows found"
    }
    
    Write-Host ""
}

# ----------------------------- Run all phases --------------------------------
Phase1-Persistence
Phase2-RouterInit
Phase3-EditorHooks
Phase4-NpmPackages
Phase5-GitCommits
Phase6-CampaignMarkers
Phase7-WorkflowInjection

# ----------------------------- Summary --------------------------------------
$END_TIME = Get-Date
$DURATION = New-TimeSpan -Start $START_TIME -End $END_TIME

Write-Host "==============================================================="
Write-Host "  SUMMARY  (host=$env:COMPUTERNAME  duration=$([int]$DURATION.TotalSeconds)s)"
Write-Host "==============================================================="
Write-Host "  CRITICAL findings: $CRITICAL"
Write-Host "  HIGH findings:     $HIGH"
Write-Host "  EXPOSURE findings: $EXPOSURE"
Write-Host ""

if ($CRITICAL -gt 0) {
    Write-Host "  VERDICT: [CRIT] LIKELY COMPROMISED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  REMEDIATION (in order - CRITICAL):" -ForegroundColor Red
    Write-Host "    1. DISABLE persistence (Unregister-ScheduledTask / Remove-Item Registry)"
    Write-Host "    2. Remove persistence files"
    Write-Host "    3. THEN rotate creds (npm, GitHub PAT, AWS, Vault, K8s)"
    Write-Host "    4. Block DNS: *.getsession.org, api.masscan.cloud"
    Write-Host "    5. Reimage host"
    $EXIT_CODE = 3
}
elseif ($HIGH -gt 0) {
    Write-Host "  VERDICT: [HIGH] PERSISTENCE HOOKS PRESENT" -ForegroundColor Yellow
    Write-Host "  Action: Remove hooks, audit recent activity, rotate creds"
    $EXIT_CODE = 2
}
elseif ($EXPOSURE -gt 0) {
    Write-Host "  VERDICT: [EXPO] EXPOSED - vulnerable package installed" -ForegroundColor Cyan
    Write-Host "  Action: Uninstall affected versions, rotate creds (precautionary)"
    $EXIT_CODE = 1
}
else {
    Write-Host "  VERDICT: [OK] CLEAN - no indicators found" -ForegroundColor Green
    $EXIT_CODE = 0
}

Write-Host "==============================================================="

exit $EXIT_CODE