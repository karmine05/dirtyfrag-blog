#!/bin/bash
# ============================================================================
# Mini Shai-Hulud TanStack worm scanner (FLEET VERSION - DEEP SCAN)
# CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx
#
# For Fleet deployment - runs FULL DEEP SCAN by default (~5min).
# Comprehensive detection across entire filesystem.
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
#   3 = CRITICAL  (payload file / system persistence found — likely compromised)
# ============================================================================

set -uo pipefail

# ----------------------------- Configuration --------------------------------
# Full deep scan mode - comprehensive filesystem search
MODE="deep"
TIMEOUT_SEC=300
START_TIME=$(date +%s)

# IOC table
ROUTER_INIT_SHA256="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
TANSTACK_RUNNER_SHA256="2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
DEAD_DROP_AUTHOR_EMAIL="claude@users.noreply.github.com"
VOIC_PRODROUCES_AUTHOR="voicproducoes"  # Compromised GitHub account
TANSTACK_SETUP_COMMIT="79ac49eedf774dd4b0cfa308722bc463cfe5885c"
CAMPAIGN_SALT="svksjrhjkcejg"
CAMPAIGN_STRING="IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
C2_DOMAIN="getsession.org"
C2_API="masscan.cloud"

# Compromised package-version pins (from Socket.dev blog + TanStack postmortem)
COMPROMISED_PKGS=(
  # @beproduct
  "@beproduct/nestjs-auth@0.1.10"
  "@beproduct/nestjs-auth@0.1.11"
  "@beproduct/nestjs-auth@0.1.12"
  "@beproduct/nestjs-auth@0.1.13"
  "@beproduct/nestjs-auth@0.1.14"
  "@beproduct/nestjs-auth@0.1.15"
  "@beproduct/nestjs-auth@0.1.16"
  "@beproduct/nestjs-auth@0.1.17"
  "@beproduct/nestjs-auth@0.1.18"
  "@beproduct/nestjs-auth@0.1.19"
  "@beproduct/nestjs-auth@0.1.2"
  "@beproduct/nestjs-auth@0.1.3"
  "@beproduct/nestjs-auth@0.1.4"
  "@beproduct/nestjs-auth@0.1.5"
  "@beproduct/nestjs-auth@0.1.6"
  "@beproduct/nestjs-auth@0.1.7"
  "@beproduct/nestjs-auth@0.1.8"
  "@beproduct/nestjs-auth@0.1.9"
  # @cap-js
  "@cap-js/db-service@2.10.1"
  "@cap-js/postgres@2.2.2"
  "@cap-js/sqlite@2.2.2"
  # @dirigible-ai
  "@dirigible-ai/sdk@0.6.2"
  "@dirigible-ai/sdk@0.6.3"
  # @draftauth
  "@draftauth/client@0.2.1"
  "@draftauth/client@0.2.2"
  "@draftauth/core@0.13.1"
  "@draftauth/core@0.13.2"
  # @draftlab
  "@draftlab/auth@0.24.1"
  "@draftlab/auth@0.24.2"
  "@draftlab/auth-router@0.5.1"
  "@draftlab/auth-router@0.5.2"
  "@draftlab/db@0.16.1"
  "@draftlab/db@0.16.2"
  # @mesadev
  "@mesadev/rest@0.28.3"
  "@mesadev/saguaro@0.4.22"
  "@mesadev/sdk@0.28.3"
  # @mistralai
  "@mistralai/mistralai@2.2.2"
  "@mistralai/mistralai@2.2.3"
  "@mistralai/mistralai@2.2.4"
  "@mistralai/mistralai-azure@1.7.1"
  "@mistralai/mistralai-azure@1.7.2"
  "@mistralai/mistralai-azure@1.7.3"
  "@mistralai/mistralai-gcp@1.7.1"
  "@mistralai/mistralai-gcp@1.7.2"
  "@mistralai/mistralai-gcp@1.7.3"
  # @ml-toolkit-ts
  "@ml-toolkit-ts/preprocessing@1.0.2"
  "@ml-toolkit-ts/preprocessing@1.0.3"
  "@ml-toolkit-ts/xgboost@1.0.3"
  "@ml-toolkit-ts/xgboost@1.0.4"
  # @opensearch-project
  "@opensearch-project/opensearch@3.6.2"
  # @squawk
  "@squawk/airport-data@0.7.4"
  "@squawk/airport-data@0.7.5"
  "@squawk/airport-data@0.7.6"
  "@squawk/airport-data@0.7.7"
  "@squawk/airport-data@0.7.8"
  "@squawk/airports@0.6.2"
  "@squawk/airports@0.6.3"
  "@squawk/airports@0.6.4"
  "@squawk/airports@0.6.5"
  "@squawk/airports@0.6.6"
  "@squawk/airspace@0.8.1"
  "@squawk/airspace@0.8.2"
  "@squawk/airspace@0.8.3"
  "@squawk/airspace@0.8.4"
  "@squawk/airspace@0.8.5"
  "@squawk/airspace-data@0.5.3"
  "@squawk/airspace-data@0.5.4"
  "@squawk/airspace-data@0.5.5"
  "@squawk/airspace-data@0.5.6"
  "@squawk/airspace-data@0.5.7"
  "@squawk/airway-data@0.5.4"
  "@squawk/airway-data@0.5.5"
  "@squawk/airway-data@0.5.6"
  "@squawk/airway-data@0.5.7"
  "@squawk/airway-data@0.5.8"
  "@squawk/airways@0.4.2"
  "@squawk/airways@0.4.3"
  "@squawk/airways@0.4.4"
  "@squawk/airways@0.4.5"
  "@squawk/airways@0.4.6"
  "@squawk/fix-data@0.6.4"
  "@squawk/fix-data@0.6.5"
  "@squawk/fix-data@0.6.6"
  "@squawk/fix-data@0.6.7"
  "@squawk/fix-data@0.6.8"
  "@squawk/fixes@0.3.2"
  "@squawk/fixes@0.3.3"
  "@squawk/fixes@0.3.4"
  "@squawk/fixes@0.3.5"
  "@squawk/fixes@0.3.6"
  "@squawk/flight-math@0.5.4"
  "@squawk/flight-math@0.5.5"
  "@squawk/flight-math@0.5.6"
  "@squawk/flight-math@0.5.7"
  "@squawk/flight-math@0.5.8"
  "@squawk/flightplan@0.5.2"
  "@squawk/flightplan@0.5.3"
  "@squawk/flightplan@0.5.4"
  "@squawk/flightplan@0.5.5"
  "@squawk/flightplan@0.5.6"
  "@squawk/geo@0.4.4"
  "@squawk/geo@0.4.5"
  "@squawk/geo@0.4.6"
  "@squawk/geo@0.4.7"
  "@squawk/geo@0.4.8"
  "@squawk/icao-registry@0.5.2"
  "@squawk/icao-registry@0.5.3"
  "@squawk/icao-registry@0.5.4"
  "@squawk/icao-registry@0.5.5"
  "@squawk/icao-registry@0.5.6"
  "@squawk/icao-registry-data@0.8.4"
  "@squawk/icao-registry-data@0.8.5"
  "@squawk/icao-registry-data@0.8.6"
  "@squawk/icao-registry-data@0.8.7"
  "@squawk/icao-registry-data@0.8.8"
  "@squawk/mcp@0.9.1"
  "@squawk/mcp@0.9.2"
  "@squawk/mcp@0.9.3"
  "@squawk/mcp@0.9.4"
  "@squawk/mcp@0.9.5"
  "@squawk/navaid-data@0.6.4"
  "@squawk/navaid-data@0.6.5"
  "@squawk/navaid-data@0.6.6"
  "@squawk/navaid-data@0.6.7"
  "@squawk/navaid-data@0.6.8"
  "@squawk/navaids@0.4.2"
  "@squawk/navaids@0.4.3"
  "@squawk/navaids@0.4.4"
  "@squawk/navaids@0.4.5"
  "@squawk/navaids@0.4.6"
  "@squawk/notams@0.3.10"
  "@squawk/notams@0.3.6"
  "@squawk/notams@0.3.7"
  "@squawk/notams@0.3.8"
  "@squawk/notams@0.3.9"
  "@squawk/procedure-data@0.7.3"
  "@squawk/procedure-data@0.7.4"
  "@squawk/procedure-data@0.7.5"
  "@squawk/procedure-data@0.7.6"
  "@squawk/procedure-data@0.7.7"
  "@squawk/procedures@0.5.2"
  "@squawk/procedures@0.5.3"
  "@squawk/procedures@0.5.4"
  "@squawk/procedures@0.5.5"
  "@squawk/procedures@0.5.6"
  "@squawk/types@0.8.1"
  "@squawk/types@0.8.2"
  "@squawk/types@0.8.3"
  "@squawk/types@0.8.4"
  "@squawk/types@0.8.5"
  "@squawk/units@0.4.3"
  "@squawk/units@0.4.4"
  "@squawk/units@0.4.5"
  "@squawk/units@0.4.6"
  "@squawk/units@0.4.7"
  "@squawk/weather@0.5.10"
  "@squawk/weather@0.5.6"
  "@squawk/weather@0.5.7"
  "@squawk/weather@0.5.8"
  "@squawk/weather@0.5.9"
  # @supersurkhet
  "@supersurkhet/cli@0.0.2"
  "@supersurkhet/cli@0.0.3"
  "@supersurkhet/cli@0.0.4"
  "@supersurkhet/cli@0.0.5"
  "@supersurkhet/cli@0.0.6"
  "@supersurkhet/cli@0.0.7"
  "@supersurkhet/sdk@0.0.2"
  "@supersurkhet/sdk@0.0.3"
  "@supersurkhet/sdk@0.0.4"
  "@supersurkhet/sdk@0.0.5"
  "@supersurkhet/sdk@0.0.6"
  "@supersurkhet/sdk@0.0.7"
  # @tallyui
  "@tallyui/components@1.0.1"
  "@tallyui/components@1.0.2"
  "@tallyui/components@1.0.3"
  "@tallyui/connector-medusa@1.0.1"
  "@tallyui/connector-medusa@1.0.2"
  "@tallyui/connector-medusa@1.0.3"
  "@tallyui/connector-shopify@1.0.1"
  "@tallyui/connector-shopify@1.0.2"
  "@tallyui/connector-shopify@1.0.3"
  "@tallyui/connector-vendure@1.0.1"
  "@tallyui/connector-vendure@1.0.2"
  "@tallyui/connector-vendure@1.0.3"
  "@tallyui/connector-woocommerce@1.0.1"
  "@tallyui/connector-woocommerce@1.0.2"
  "@tallyui/connector-woocommerce@1.0.3"
  "@tallyui/core@0.2.1"
  "@tallyui/core@0.2.2"
  "@tallyui/core@0.2.3"
  "@tallyui/database@1.0.1"
  "@tallyui/database@1.0.2"
  "@tallyui/database@1.0.3"
  "@tallyui/pos@0.1.1"
  "@tallyui/pos@0.1.2"
  "@tallyui/pos@0.1.3"
  "@tallyui/storage-sqlite@0.2.1"
  "@tallyui/storage-sqlite@0.2.2"
  "@tallyui/storage-sqlite@0.2.3"
  "@tallyui/theme@0.2.1"
  "@tallyui/theme@0.2.2"
  "@tallyui/theme@0.2.3"
  # @tanstack
  "@tanstack/arktype-adapter@1.166.12"
  "@tanstack/arktype-adapter@1.166.15"
  "@tanstack/eslint-plugin-router@1.161.12"
  "@tanstack/eslint-plugin-router@1.161.9"
  "@tanstack/eslint-plugin-start@0.0.4"
  "@tanstack/eslint-plugin-start@0.0.7"
  "@tanstack/history@1.161.12"
  "@tanstack/history@1.161.9"
  "@tanstack/nitro-v2-vite-plugin@1.154.12"
  "@tanstack/nitro-v2-vite-plugin@1.154.15"
  "@tanstack/react-router@1.169.5"
  "@tanstack/react-router@1.169.8"
  "@tanstack/react-router-devtools@1.166.16"
  "@tanstack/react-router-devtools@1.166.19"
  "@tanstack/react-router-ssr-query@1.166.15"
  "@tanstack/react-router-ssr-query@1.166.18"
  "@tanstack/react-start@1.167.68"
  "@tanstack/react-start@1.167.71"
  "@tanstack/react-start-client@1.166.51"
  "@tanstack/react-start-client@1.166.54"
  "@tanstack/react-start-rsc@0.0.47"
  "@tanstack/react-start-rsc@0.0.50"
  "@tanstack/react-start-server@1.166.55"
  "@tanstack/react-start-server@1.166.58"
  "@tanstack/router-cli@1.166.46"
  "@tanstack/router-cli@1.166.49"
  "@tanstack/router-core@1.169.5"
  "@tanstack/router-core@1.169.8"
  "@tanstack/router-devtools@1.166.16"
  "@tanstack/router-devtools@1.166.19"
  "@tanstack/router-devtools-core@1.167.6"
  "@tanstack/router-devtools-core@1.167.9"
  "@tanstack/router-generator@1.166.45"
  "@tanstack/router-generator@1.166.48"
  "@tanstack/router-plugin@1.167.38"
  "@tanstack/router-plugin@1.167.41"
  "@tanstack/router-ssr-query-core@1.168.3"
  "@tanstack/router-ssr-query-core@1.168.6"
  "@tanstack/router-utils@1.161.11"
  "@tanstack/router-utils@1.161.14"
  "@tanstack/router-vite-plugin@1.166.53"
  "@tanstack/router-vite-plugin@1.166.56"
  "@tanstack/solid-router@1.169.5"
  "@tanstack/solid-router@1.169.8"
  "@tanstack/solid-router-devtools@1.166.16"
  "@tanstack/solid-router-devtools@1.166.19"
  "@tanstack/solid-router-ssr-query@1.166.15"
  "@tanstack/solid-router-ssr-query@1.166.18"
  "@tanstack/solid-start@1.167.65"
  "@tanstack/solid-start@1.167.68"
  "@tanstack/solid-start-client@1.166.50"
  "@tanstack/solid-start-client@1.166.53"
  "@tanstack/solid-start-server@1.166.54"
  "@tanstack/solid-start-server@1.166.57"
  "@tanstack/start-client-core@1.168.5"
  "@tanstack/start-client-core@1.168.8"
  "@tanstack/start-fn-stubs@1.161.12"
  "@tanstack/start-fn-stubs@1.161.9"
  "@tanstack/start-plugin-core@1.169.23"
  "@tanstack/start-plugin-core@1.169.26"
  "@tanstack/start-server-core@1.167.33"
  "@tanstack/start-server-core@1.167.36"
  "@tanstack/start-static-server-functions@1.166.44"
  "@tanstack/start-static-server-functions@1.166.47"
  "@tanstack/start-storage-context@1.166.38"
  "@tanstack/start-storage-context@1.166.41"
  "@tanstack/valibot-adapter@1.166.12"
  "@tanstack/valibot-adapter@1.166.15"
  "@tanstack/virtual-file-routes@1.161.10"
  "@tanstack/virtual-file-routes@1.161.13"
  "@tanstack/vue-router@1.169.5"
  "@tanstack/vue-router@1.169.8"
  "@tanstack/vue-router-devtools@1.166.16"
  "@tanstack/vue-router-devtools@1.166.19"
  "@tanstack/vue-router-ssr-query@1.166.15"
  "@tanstack/vue-router-ssr-query@1.166.18"
  "@tanstack/vue-start@1.167.61"
  "@tanstack/vue-start@1.167.64"
  "@tanstack/vue-start-client@1.166.46"
  "@tanstack/vue-start-client@1.166.49"
  "@tanstack/vue-start-server@1.166.50"
  "@tanstack/vue-start-server@1.166.53"
  "@tanstack/zod-adapter@1.166.12"
  "@tanstack/zod-adapter@1.166.15"
  # @taskflow-corp
  "@taskflow-corp/cli@0.1.24"
  "@taskflow-corp/cli@0.1.25"
  "@taskflow-corp/cli@0.1.26"
  "@taskflow-corp/cli@0.1.27"
  "@taskflow-corp/cli@0.1.28"
  "@taskflow-corp/cli@0.1.29"
  # @tolka
  "@tolka/cli@1.0.2"
  "@tolka/cli@1.0.3"
  "@tolka/cli@1.0.4"
  "@tolka/cli@1.0.5"
  "@tolka/cli@1.0.6"
  # @uipath
  "@uipath/access-policy-sdk@0.3.1"
  "@uipath/access-policy-tool@0.3.1"
  "@uipath/admin-tool@0.1.1"
  "@uipath/agent-sdk@1.0.2"
  "@uipath/agent-tool@1.0.1"
  "@uipath/agent.sdk@0.0.18"
  "@uipath/aops-policy-tool@0.3.1"
  "@uipath/ap-chat@1.5.7"
  "@uipath/api-workflow-tool@1.0.1"
  "@uipath/apollo-core@5.9.2"
  "@uipath/apollo-react@4.24.5"
  "@uipath/apollo-wind@2.16.2"
  "@uipath/auth@1.0.1"
  "@uipath/case-tool@1.0.1"
  "@uipath/cli@1.0.1"
  "@uipath/codedagent-tool@1.0.1"
  "@uipath/codedagents-tool@0.1.12"
  "@uipath/codedapp-tool@1.0.1"
  "@uipath/common@1.0.1"
  "@uipath/context-grounding-tool@0.1.1"
  "@uipath/data-fabric-tool@1.0.2"
  "@uipath/docsai-tool@1.0.1"
  "@uipath/filesystem@1.0.1"
  "@uipath/flow-tool@1.0.2"
  "@uipath/functions-tool@1.0.1"
  "@uipath/gov-tool@0.3.1"
  "@uipath/identity-tool@0.1.1"
  "@uipath/insights-sdk@1.0.1"
  "@uipath/insights-tool@1.0.1"
  "@uipath/integrationservice-sdk@1.0.2"
  "@uipath/integrationservice-tool@1.0.2"
  "@uipath/llmgw-tool@1.0.1"
  "@uipath/maestro-sdk@1.0.1"
  "@uipath/maestro-tool@1.0.1"
  "@uipath/orchestrator-tool@1.0.1"
  "@uipath/packager-tool-apiworkflow@0.0.19"
  "@uipath/packager-tool-bpmn@0.0.9"
  "@uipath/packager-tool-case@0.0.9"
  "@uipath/packager-tool-connector@0.0.19"
  "@uipath/packager-tool-flow@0.0.19"
  "@uipath/packager-tool-functions@0.1.1"
  "@uipath/packager-tool-webapp@1.0.6"
  "@uipath/packager-tool-workflowcompiler@0.0.16"
  "@uipath/packager-tool-workflowcompiler-browser@0.0.34"
  "@uipath/platform-tool@1.0.1"
  "@uipath/project-packager@1.1.16"
  "@uipath/resource-tool@1.0.1"
  "@uipath/resourcecatalog-tool@0.1.1"
  "@uipath/resources-tool@0.1.11"
  "@uipath/robot@1.3.4"
  "@uipath/rpa-legacy-tool@1.0.1"
  "@uipath/rpa-tool@0.9.5"
  "@uipath/solution-packager@0.0.35"
  "@uipath/solution-tool@1.0.1"
  "@uipath/solutionpackager-sdk@1.0.11"
  "@uipath/solutionpackager-tool-core@0.0.34"
  "@uipath/tasks-tool@1.0.1"
  "@uipath/telemetry@0.0.7"
  "@uipath/test-manager-tool@1.0.2"
  "@uipath/tool-workflowcompiler@0.0.12"
  "@uipath/traces-tool@1.0.1"
  "@uipath/ui-widgets-multi-file-upload@1.0.1"
  "@uipath/uipath-python-bridge@1.0.1"
  "@uipath/vertical-solutions-tool@1.0.1"
  "@uipath/vss@0.1.6"
  "@uipath/widget.sdk@1.2.3"
  # (unscoped)
  "agentwork-cli@0.1.4"
  "agentwork-cli@0.1.5"
  "cmux-agent-mcp@0.1.3"
  "cmux-agent-mcp@0.1.4"
  "cmux-agent-mcp@0.1.5"
  "cmux-agent-mcp@0.1.6"
  "cmux-agent-mcp@0.1.7"
  "cmux-agent-mcp@0.1.8"
  "cross-stitch@1.1.3"
  "cross-stitch@1.1.4"
  "cross-stitch@1.1.5"
  "cross-stitch@1.1.6"
  "cross-stitch@1.1.7"
  "git-branch-selector@1.3.3"
  "git-branch-selector@1.3.4"
  "git-branch-selector@1.3.5"
  "git-branch-selector@1.3.6"
  "git-branch-selector@1.3.7"
  "git-git-git@1.0.10"
  "git-git-git@1.0.11"
  "git-git-git@1.0.12"
  "git-git-git@1.0.8"
  "git-git-git@1.0.9"
  "intercom-client@7.0.4"
  "mbt@1.2.48"
  "ml-toolkit-ts@1.0.4"
  "ml-toolkit-ts@1.0.5"
  "nextmove-mcp@0.1.3"
  "nextmove-mcp@0.1.4"
  "nextmove-mcp@0.1.5"
  "nextmove-mcp@0.1.6"
  "nextmove-mcp@0.1.7"
  "safe-action@0.8.3"
  "safe-action@0.8.4"
  "ts-dna@3.0.1"
  "ts-dna@3.0.2"
  "ts-dna@3.0.3"
  "ts-dna@3.0.4"
  "ts-dna@3.0.5"
  "wot-api@0.8.1"
  "wot-api@0.8.2"
  "wot-api@0.8.3"
  "wot-api@0.8.4"
)

# ----------------------------- platform setup -------------------------------
OS_RAW="$(uname -s)"
case "$OS_RAW" in
  Darwin) PLATFORM="macos"; HOME_ROOTS=(/Users /home) ;;
  Linux)  PLATFORM="linux"; HOME_ROOTS=(/home /root) ;;
  *) printf 'Unsupported OS: %s\n' "$OS_RAW"; exit 1 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
else
  SHA_CMD=""
fi

HOSTNAME_S="$(hostname 2>/dev/null || echo unknown)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ----------------------------- counters & buffers ---------------------------
CRITICAL=0; HIGH=0; EXPOSURE=0

bump_crit()  { CRITICAL=$((CRITICAL+1)); printf '[CRITICAL] %s\n' "$1"; }
bump_high()  { HIGH=$((HIGH+1));         printf '[HIGH]     %s\n' "$1"; }
bump_expo()  { EXPOSURE=$((EXPOSURE+1)); printf '[EXPOSED]  %s\n' "$1"; }

# ----------------------------- header ---------------------------------------
printf '═══════════════════════════════════════════════════════════════\n'
printf '  Mini Shai-Hulud TanStack worm scan [DEEP SCAN]\n'
printf '  CVE-2026-45321 | GHSA-g7cv-rxg3-hmpx\n'
printf '  host=%s  platform=%s  time=%s\n' "$HOSTNAME_S" "$PLATFORM" "$TS"
printf '═══════════════════════════════════════════════════════════════\n\n'

# ----------------------------- Helper: timeout guard ------------------------
check_timeout() {
  local now=$(date +%s)
  local elapsed=$((now - START_TIME))
  if [[ $elapsed -gt $TIMEOUT_SEC ]]; then
    printf '\n[TIMEOUT] Scan exceeded %s seconds, stopping\n' "$TIMEOUT_SEC"
    return 1
  fi
  return 0
}

# ----------------------------- Phase 1: host-level persistence --------------
phase1_persistence() {
  printf '[*] Phase 1 — host-level persistence (LaunchAgents/systemd)\n'
  
  if [[ "$PLATFORM" == "macos" ]]; then
    printf '    Scanning /Users for malicious LaunchAgents...\n'
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      bump_crit "LaunchAgent: $p"
    done < <(find /Users -maxdepth 5 -path '*/Library/LaunchAgents/com.user.gh-token-monitor.plist' 2>/dev/null)
    
    # Check content for malicious patterns in ALL LaunchAgents
    printf '    Scanning LaunchAgents for malicious content...\n'
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if grep -qE 'gh-token-monitor|getsession\.org|router_init' "$p" 2>/dev/null; then
        bump_crit "LaunchAgent with malicious content: $p"
      fi
    done < <(find /Users -maxdepth 5 -path '*/Library/LaunchAgents/*.plist' 2>/dev/null)
    
  elif [[ "$PLATFORM" == "linux" ]]; then
    printf '    Scanning for systemd persistence...\n'
    for root in "${HOME_ROOTS[@]}"; do
      [[ -d "$root" ]] || continue
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        bump_crit "Persistence: $p"
      done < <(find "$root" -maxdepth 7 \( \
                  -path '*/.config/systemd/user/gh-token-monitor.service' \
               -o -path '*/.local/bin/gh-token-monitor.sh' \
               \) 2>/dev/null)
    done
  fi
  
  [[ $CRITICAL -eq 0 ]] && printf '    [OK] none found\n'
  printf '\n'
}

# ----------------------------- Phase 2: payload file hunt -------------------
# Hunts BOTH payload filenames: router_init.js (primary) and
# tanstack_runner.js (secondary, from orphan commit 79ac49ee).
# Hash-verifies every match. Does NOT early-exit on first match — we want
# the full count for forensics.
phase2_router_init() {
  printf '[*] Phase 2 — payload files (router_init.js + tanstack_runner.js)\n'

  local count=0
  local sha_count=0

  hunt_payload() {
    local search_root="$1" payload_name="$2" expected_sha="$3" label_prefix="$4"
    while IFS= read -r match; do
      [[ -z "$match" ]] && continue
      count=$((count+1))
      local sha=""
      if [[ -n "$SHA_CMD" ]]; then
        sha=$($SHA_CMD "$match" 2>/dev/null | awk '{print $1}')
      fi
      if [[ -n "$sha" && "$sha" == "$expected_sha" ]]; then
        sha_count=$((sha_count+1))
        bump_crit "${label_prefix}${payload_name} (SHA256 MATCH): $match"
      elif [[ -n "$sha" ]]; then
        # Filename match but hash differs — could be a variant or unrelated file
        # with the same name. Still surface as critical because the filename is
        # specific to this campaign; reviewer can decide.
        bump_crit "${label_prefix}${payload_name} (filename match, sha256=${sha:0:16}...): $match"
      else
        bump_crit "${label_prefix}${payload_name} (filename match, no SHA tool): $match"
      fi
    done < <(find "$search_root" -maxdepth 10 -type f -name "$payload_name" 2>/dev/null)
  }

  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    printf '    Scanning %s...\n' "$root"
    hunt_payload "$root" "router_init.js"     "$ROUTER_INIT_SHA256"     ""
    hunt_payload "$root" "tanstack_runner.js" "$TANSTACK_RUNNER_SHA256" ""
  done

  printf '    Scanning global npm directories...\n'
  for gnm in /usr/local/lib/node_modules /opt/homebrew/lib/node_modules /usr/lib/node_modules; do
    [[ -d "$gnm" ]] || continue
    hunt_payload "$gnm" "router_init.js"     "$ROUTER_INIT_SHA256"     "GLOBAL "
    hunt_payload "$gnm" "tanstack_runner.js" "$TANSTACK_RUNNER_SHA256" "GLOBAL "
  done

  if [[ $count -eq 0 ]]; then
    printf '    [OK] none found\n'
  else
    printf '    Found %s payload file(s), %s with confirmed-bad SHA256\n' "$count" "$sha_count"
  fi
  printf '\n'
}

# ----------------------------- Phase 3: editor-hook persistence -------------
phase3_editor_hooks() {
  printf '[*] Phase 3 — editor hooks (.claude/.vscode)\n'
  
  local count=0
  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      count=$((count+1))
      bump_high "editor hook: $p"
    done < <(find "$root" -maxdepth 10 \( \
                -path '*/.claude/router_runtime.js' \
             -o -path '*/.claude/setup.mjs' \
             -o -path '*/.vscode/setup.mjs' \
             \) -type f 2>/dev/null)
  done
  
  [[ $count -eq 0 ]] && printf '    [OK] none found\n'
  printf '\n'
}

# ----------------------------- Phase 4: compromised npm packages ------------
phase4_npm_packages() {
  printf '[*] Phase 4 — compromised npm packages\n'
  
  local count=0
  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    printf '    Scanning %s for compromised packages...\n' "$root"
    
    while IFS= read -r nm; do
      [[ -z "$nm" ]] && continue
      check_timeout || return
      
      # @tanstack/setup is the forged package — ANY version installed is critical
      if [[ -d "$nm/@tanstack/setup" ]]; then
        count=$((count+1))
        bump_crit "@tanstack/setup directory present (forged package, any version): $nm/@tanstack/setup"
      fi

      for pkgver in "${COMPROMISED_PKGS[@]}"; do
        pkg_name="${pkgver%@*}"
        pkg_ver="${pkgver##*@}"
        pj="$nm/$pkg_name/package.json"
        
        if [[ -f "$pj" ]]; then
          installed=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$pj" 2>/dev/null \
                      | head -1 | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
          if [[ "$installed" == "$pkg_ver" ]]; then
            count=$((count+1))
            bump_expo "$pkgver installed: $pj"
          fi
        fi
      done
    done < <(find "$root" -maxdepth 10 -type d -name node_modules 2>/dev/null)
  done
  
  [[ $count -eq 0 ]] && printf '    [OK] no compromised versions found\n'
  printf '\n'
}

# ----------------------------- Phase 5: git dead-drop commits ---------------
phase5_git_commits() {
  printf '[*] Phase 5 — git dead-drop commits\n'
  
  [[ ! -x "$(command -v git)" ]] && printf '    [SKIP] git not available\n' && return
  
  local count=0
  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    printf '    Scanning git repos in %s...\n' "$root"
    
    while IFS= read -r gitdir; do
      [[ -z "$gitdir" ]] && continue
      check_timeout || return
      
      repo="${gitdir%/.git}"
      
      # Check for claude@ dead-drop commits
      drops=$(git -C "$repo" log --all --author="$DEAD_DROP_AUTHOR_EMAIL" \
                --pretty='%h %s' 2>/dev/null | head -10)
      
      if [[ -n "$drops" ]]; then
        count=$((count+1))
        if echo "$drops" | grep -qE 'chore: update dependencies|dependabout'; then
          bump_high "campaign commits (claude@) in: $repo"
        else
          printf '    [INFO] Claude commits in %s (review manually):\n' "$repo"
          echo "$drops" | sed 's/^/      /'
        fi
      fi
      
      # Check for voicproducoes (compromised account) commits
      voic_commits=$(git -C "$repo" log --all --author="$VOIC_PRODROUCES_AUTHOR" \
                     --pretty='%h %s' 2>/dev/null | head -10)
      
      if [[ -n "$voic_commits" ]]; then
        count=$((count+1))
        if echo "$voic_commits" | grep -qE 'Mini Shai-Hulud|tanstack|router'; then
          bump_high "campaign commits (voicproducoes) in: $repo"
        else
          printf '    [INFO] voicproducoes commits in %s (review manually):\n' "$repo"
          echo "$voic_commits" | sed 's/^/      /'
        fi
      fi
      
      # Check for tanstack/setup commit reference in .gitmodules or package.json
      if grep -qR "$TANSTACK_SETUP_COMMIT" "$repo" 2>/dev/null; then
        bump_crit "tanstack/setup commit reference found in: $repo"
      fi
      
    done < <(find "$root" -maxdepth 8 -type d -name .git 2>/dev/null)
  done
  
  [[ $count -eq 0 ]] && printf '    [OK] no campaign-pattern commits found\n'
  printf '\n'
}

# ----------------------------- Phase 6: campaign markers ---------------------
phase6_campaign_markers() {
  printf '[*] Phase 6 — campaign markers in package.json (deep scan)\n'
  
  local count=0
  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    printf '    Scanning package.json files in %s...\n' "$root"
    
    while IFS= read -r pj; do
      [[ -z "$pj" ]] && continue
      check_timeout || return
      
      if grep -qE "${CAMPAIGN_SALT}|${CAMPAIGN_STRING}|${DEAD_DROP_AUTHOR_EMAIL}" "$pj" 2>/dev/null; then
        count=$((count+1))
        bump_crit "campaign marker: $pj"
      fi
      
      # Check for tanstack/setup github reference with suspicious commit
      if grep -qE "github:tanstack/router.*${TANSTACK_SETUP_COMMIT}" "$pj" 2>/dev/null; then
        count=$((count+1))
        bump_crit "tanstack/setup malicious commit: $pj"
      fi
      
    done < <(find "$root" -maxdepth 10 -name package.json 2>/dev/null)
  done
  
  [[ $count -eq 0 ]] && printf '    [OK] no campaign markers found\n'
  printf '\n'
}

# ----------------------------- Phase 7: workflow injection ------------------
phase7_workflow_injection() {
  printf '[*] Phase 7 — injected GitHub workflows\n'
  
  local count=0
  for root in "${HOME_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    
    while IFS= read -r wf; do
      [[ -z "$wf" ]] && continue
      check_timeout || return
      
      if grep -qE "toJSON\(secrets\)|${C2_DOMAIN}|${C2_API}|__DAEMONIZED|router_init" "$wf" 2>/dev/null; then
        count=$((count+1))
        bump_crit "malicious workflow: $wf"
      fi
    done < <(find "$root" -maxdepth 8 -path '*/.github/workflows/*.yml' -type f 2>/dev/null)
  done
  
  [[ $count -eq 0 ]] && printf '    [OK] no malicious workflows found\n'
  printf '\n'
}

# ----------------------------- Run all phases --------------------------------
phase1_persistence
phase2_router_init
phase3_editor_hooks
phase4_npm_packages
phase5_git_commits
phase6_campaign_markers
phase7_workflow_injection

# ----------------------------- summary --------------------------------------
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

printf '═══════════════════════════════════════════════════════════════\n'
printf '  SUMMARY  (host=%s  duration=%ds)\n' "$HOSTNAME_S" "$DURATION"
printf '═══════════════════════════════════════════════════════════════\n'
printf '  CRITICAL findings: %s\n' "$CRITICAL"
printf '  HIGH findings:     %s\n' "$HIGH"
printf '  EXPOSURE findings: %s\n' "$EXPOSURE"
printf '\n'

if (( CRITICAL > 0 )); then
  printf '  VERDICT: 🔴 LIKELY COMPROMISED\n'
  printf '\n  REMEDIATION (in order - CRITICAL):\n'
  printf '    1. DISABLE persistence (launchctl unload / systemctl stop)\n'
  printf '    2. Remove persistence files\n'
  printf '    3. THEN rotate creds (npm, GitHub PAT, AWS, Vault, K8s)\n'
  printf '    4. Block DNS: *.getsession.org, api.masscan.cloud\n'
  printf '    5. Reimage host\n'
  EXIT_CODE=3
  
elif (( HIGH > 0 )); then
  printf '  VERDICT: 🟠 PERSISTENCE HOOKS PRESENT\n'
  printf '  Action: Remove hooks, audit recent activity, rotate creds\n'
  EXIT_CODE=2
  
elif (( EXPOSURE > 0 )); then
  printf '  VERDICT: 🟡 EXPOSED — vulnerable package installed\n'
  printf '  Action: Uninstall affected versions, rotate creds (precautionary)\n'
  EXIT_CODE=1
  
else
  printf '  VERDICT: 🟢 CLEAN — no indicators found\n'
  EXIT_CODE=0
fi

printf '═══════════════════════════════════════════════════════════════\n'
exit $EXIT_CODE
