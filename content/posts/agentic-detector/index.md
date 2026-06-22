---
title: "Seeing the AI Layer: Detecting Agents, MCP Servers, and IDE Plugins on Every Endpoint with osquery"
date: 2026-06-22T09:00:00-04:00
draft: false
tags: ["fleet", "osquery", "ai", "mcp", "detection-engineering", "security-ops", "agentic-ai", "supply-chain", "threat-hunting"]
categories: ["security-ops"]
description: "agentic-detector is a cross-platform osquery extension that surfaces the AI software layer — MCP servers, agent CLIs, IDE plugins, desktop apps, live AI network sockets, and agent instruction files — through a single queryable table. This post covers why the visibility gap exists, how the extension works, and how to deploy it across your fleet."
summary: "Your EDR knows about processes and network connections. Your MDM knows about installed apps. Neither one knows that someone on your team is running an npx-fetched MCP server that has shell-exec capability and a plaintext secret baked into its config. agentic-detector is a cross-platform osquery extension that fixes that. One table — ai_tools — gives you the full AI software inventory per host: MCP servers, agent CLIs, IDE plugins, desktop apps, live network sockets, and the agent instruction files that tell AI what it's allowed to do. Deployable through Fleet in minutes."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

> **One sentence:** your fleet has an AI software layer that your existing tools can't see — `agentic-detector` puts a queryable osquery table over it.

| | |
|---|---|
| **What it is** | A cross-platform osquery extension (Go) that exposes AI tooling as a queryable table |
| **What it detects** | MCP servers, agent CLIs, AI desktop apps, IDE plugins, live AI/MCP network sockets, agent instruction files |
| **How it surfaces risk** | SHA-256 fingerprints + `risk_flags` covering supply-chain exposure, inferred capabilities, plaintext secrets, agent autonomy posture, prompt injection |
| **What it won't do** | Execute discovered binaries, connect to MCP servers, emit secret values, or take any remediation action |
| **Deploy path** | Fleet Premium (fleetd/orbit auto-distribution) or local `osqueryi` in under five minutes |
| **Repo** | [github.com/karmine05/agentic-detector](https://github.com/karmine05/agentic-detector) |

---

## The visibility gap

Traditional endpoint tooling — EDR, MDM, even osquery's built-in tables — was built for a world where software runs from an installer, a package manager, or an IT-approved image. The AI tooling layer doesn't work that way.

An MCP server can be `npx`-fetched on first run, no installation step. An AI agent CLI can be `pip install`-ed into a user-owned virtualenv. A `CLAUDE.md` file can be dropped anywhere in a project tree and immediately start shaping what an AI agent is allowed to do on that machine. None of these show up in MDM enrollment records. Very few show up as installed applications. Some don't even appear as persistent processes.

At the same time, these tools carry real exposure:

- An MCP server launched via `npx <package>@latest` fetches and executes code from npm at every restart. The package version is not pinned — what runs today may not be what runs tomorrow.
- An MCP server with inferred `shell_exec` capability wired to a Claude Desktop config can run arbitrary shell commands on behalf of an AI agent. The user who wired it up may not have read the docs that far.
- A `CLAUDE.md` file that's world-writable can be modified by any local user to inject instructions the AI agent will follow.
- A running agent with `--dangerously-skip-permissions` in its process flags is operating without the confirmation dialogs that exist for a reason.

None of this is hypothetical. These configurations exist on developer endpoints right now. The question is whether you know about them.

---

## The `ai_tools` table

`agentic-detector` adds one table to osquery: `ai_tools`. Every row is an AI tool — presence in the table is the signal, not a column called `is_ai`.

A `kind` column separates the six row types:

| `kind` | What the row represents |
|---|---|
| `mcp_server` | An MCP server declared in any client config (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Zed, Cline, Roo, Continue) and/or a running MCP server process |
| `ide_plugins` | An installed AI editor plugin (VS Code family incl. Cursor/Windsurf/VSCodium, JetBrains, Zed, Sublime, Neovim/Vim, Emacs) |
| `agents` | An installed AI agent CLI (Claude Code, Gemini CLI, Codex, aider, goose, opencode, Cline, Amazon Q/Kiro) |
| `apps` | An installed AI desktop app (Claude Desktop, ChatGPT, Ollama, LM Studio, Jan, Perplexity, Cursor, Windsurf, and others) |
| `sockets` | A live AI/MCP network socket — local inference/MCP listener or outbound AI/MCP egress |
| `agent_instruction` | An agent instruction file the AI auto-loads (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.github/copilot-instructions.md`, Cursor `.mdc` rules) |

{{< figure src="images/ai-tools-inventory.png" alt="osqueryi result: SELECT type, name, category, running FROM ai_tools LIMIT 20 — showing sockets (bun, nfs, Ollama, Claude Helper), mcp_server rows (fleet-mcp, 21st-dev-magic, claude-flow, ruflo, docker-mcp, context7, deepwiki, playwright), and an ide_plugins row for Cline" caption="Twenty rows from a live host: sockets, MCP servers across multiple clients, and an IDE plugin — all from one table." >}}

The full column set: `kind, name, identifier, category, location, source, version, path, endpoint, running, pid, port, risk_flags, sha256, uid, username, detail`.

The `detail` column is compact JSON carrying kind-specific extras: `transport`, `args`, `env_keys` (names only — never values), `capabilities`, `launch_hash`, `permission_mode`, `markers`, and others depending on kind.

One design choice worth calling out: the extension enumerates **all home directories** on the host (`/Users/*`, `/home/*`, `/root`, `C:\Users\*`) — not just the daemon account. When Fleet's `fleetd` runs it as root, you see the full multi-user picture. Running unprivileged gives you partial rows on homes you can't read, rather than a silent miss.

---

## What risk_flags tells you

Every row carries a `risk_flags` column — a comma-separated set of tokens that surface specific exposures. An empty string means none were found.

| Flag | Kind | What it means |
|---|---|---|
| `remote_fetch_exec` | `mcp_server` | Server is launched via `npx`/`uvx`/`bunx` — fetches and executes remote code at every start |
| `unpinned_dependency` | `mcp_server` | That fetched package is unpinned or `@latest` — mutable supply chain |
| `mcp_shell_exec` | `mcp_server` | Inferred capability: this server can run shell commands |
| `mcp_fs_write` | `mcp_server` | Inferred capability: this server can write to the filesystem |
| `plaintext_secret` | `mcp_server` | A secret-shaped env var name is set inline in the config (name only is flagged — the value is never read or emitted) |
| `world_readable_config` | `mcp_server` | The declaring config file is group/other-readable |
| `cleartext_endpoint` | `mcp_server` | Remote MCP reached over plain `http://` |
| `bypass_permissions` | `agents` | Agent config declares auto-approve autonomy posture |
| `auto_accept_edits` | `agents` | Same family — auto-accept without confirmation |
| `skip_permissions_runtime` | `agents` | Agent is running with an unattended flag (`--dangerously-skip-permissions`) right now |
| `injection_markers` | `agent_instruction` | File contains prompt-injection or exfiltration phrases — see `detail.markers` |
| `hidden_unicode` | `agent_instruction` | Zero-width or Unicode-tag characters present — used to smuggle hidden instructions |
| `world_writable` | `agent_instruction` | File is world-writable — any local user can modify what the agent is told to do |

{{< figure src="images/risk-flags-live.png" alt="osqueryi result: SELECT name, source AS browser, risk_flags FROM ai_tools WHERE risk_flags != '' — showing CLAUDE.md with injection_markers, claude-flow with remote_fetch_exec, ruflo with remote_fetch_exec and unpinned_dependency, docker-mcp and fleet-mcp with world_readable_config, and others" caption="Every row here is a configuration that warrants a second look — from an instruction file flagged for injection markers to MCP servers fetching unpinned remote code at every launch." >}}

Capability inference is static. The extension reads the known-server knowledge base and infers what a given MCP server is capable of from its name and configuration — it never connects to or launches the server to find out. That's an intentional no-exec posture: discovering what a suspicious binary can do by running it isn't detection, it's detonation.

---

## Example queries

These run in the Fleet live query console or in a local `osquery>` shell. Filtering on `kind` is cheap — constraint pushdown means only the relevant collectors run.

**Full AI inventory on a host:**
```sql
SELECT kind, name, category, running, risk_flags
FROM ai_tools
ORDER BY kind, name;
```

**Remote MCP servers only (the highest-risk surface):**
```sql
SELECT name, source, endpoint, risk_flags
FROM ai_tools
WHERE kind = 'mcp_server'
  AND location = 'remote';
```

**MCP servers with supply-chain exposure:**
```sql
SELECT name, path, risk_flags
FROM ai_tools
WHERE kind = 'mcp_server'
  AND risk_flags LIKE '%remote_fetch_exec%';
```

**Agents running in auto-approve mode right now:**
```sql
SELECT name, pid, path, risk_flags
FROM ai_tools
WHERE kind = 'agents'
  AND (
    risk_flags LIKE '%bypass_permissions%'
    OR risk_flags LIKE '%skip_permissions_runtime%'
  )
  AND running = '1';
```

**Agent instruction files with injection markers or hidden unicode:**
```sql
SELECT name, path, username, risk_flags, sha256
FROM ai_tools
WHERE kind = 'agent_instruction'
  AND (
    risk_flags LIKE '%injection_markers%'
    OR risk_flags LIKE '%hidden_unicode%'
  );
```

**Live AI network sockets — what's phoning home:**
```sql
SELECT name, category, endpoint, port, pid
FROM ai_tools
WHERE kind = 'sockets';
```

**Row count by kind — quick inventory shape:**
```sql
SELECT kind, count(*) AS count
FROM ai_tools
GROUP BY kind;
```

{{< figure src="images/unpinned-deps-injection.png" alt="Two osqueryi results: first shows ruflo and claude-flow both launched via npx with @latest (unpinned_dependency); second shows CLAUDE.md at /Users/dhruv/.claude/CLAUDE.md flagged with injection_markers, detail.markers = sh" caption="Top: two MCP servers fetching ruflo@latest and claude-flow@latest from npm at every start — the package that runs tomorrow is not necessarily the one that ran today. Bottom: CLAUDE.md flagged for injection markers; the markers field names the specific pattern matched." >}}

---

## How detection works under the hood

There are four mechanisms running together each time a query hits the table.

**Config parsing.** The extension reads every known MCP client config format — JSON for Claude Desktop/Code, YAML and JSON for VS Code, Cursor, Windsurf, Zed, Cline, Roo, and Continue. It handles VS Code's `servers` key separately from everyone else's `mcpServers`, Zed's nested command object, and per-project configs in `.mcp.json`, `.cursor`, `.vscode`, and `.roo` directories via a bounded walk of common dev roots.

**Process and connection snapshot.** One `gopsutil` snapshot per query feeds liveness data (`running`, `pid`), fills listening port fields, and generates the `sockets` kind rows. The snapshot is shared across all collectors in a single query — it doesn't run once per kind.

**Classification knowledge base.** `internal/classify/kb.json` (embedded at build time) maps known extension IDs, process command-line markers, inference ports, and MCP server capability tags to categories. Egress attribution is process-first: if the process owning a connection is an AI or agent tool, the socket is attributed as AI traffic regardless of destination IP. No hostname allowlists, no brittle IP matching.

**Integrity fingerprints.** Every MCP config, agent binary, app binary, and instruction file gets a SHA-256 hash in the `sha256` column. MCP server rows also carry a `launch_hash` in `detail` — a hash of the command, args, and URL — so you can detect a silently mutated launch vector (a rug-pull on the server's actual behavior) by diffing snapshots over time in your SIEM.

---

## Try it locally in five minutes

If you want to run it against your own machine before deploying, you need `osqueryi` on PATH (`brew install --cask osquery` on macOS) and either a pre-built binary from the [releases page](https://github.com/karmine05/agentic-detector/releases) or a build from source (`make build-all`).

**macOS:**

```bash
# Download and clear quarantine (binary is unsigned)
gh release download v0.2.0 -R karmine05/agentic-detector \
  -p 'agentic_detector_macos.ext'
xattr -d com.apple.quarantine agentic_detector_macos.ext

# Quick row-count sanity check
osqueryi --allow_unsafe \
  --extension "$PWD/agentic_detector_macos.ext" \
  --extensions_require=agentic_detector \
  --extensions_timeout=10 \
  "SELECT kind, count(*) FROM ai_tools GROUP BY kind"
```

`--extensions_require` is important for one-shot queries — without it, `osqueryi` exits before the extension finishes registering and you get `no such table: ai_tools`. In an interactive `osquery>` session it's not needed.

For a full interactive session: `make run` (or `make run-root` to see all users' homes).

---

## What it tells you that your current stack doesn't

A few concrete examples of things `ai_tools` surfaces that don't appear elsewhere:

An `npx`-launched MCP server doesn't exist as an installed application. It might not even have a persistent process — it may only run when Claude Desktop is open. MDM won't see it. `ps` might not either. `ai_tools` catches it from the config file.

An AI agent CLI installed via `pip install --user` lands in `~/.local/bin`. It's not in MDM's application inventory. It doesn't appear in Homebrew. `ai_tools` catches it from known binary names and install paths.

A `CLAUDE.md` in a project directory with world-writable permissions is a hijack surface — any user on the system can modify what Claude is told to do in that project. No existing tool looks for this. `ai_tools` surfaces it as `world_writable` on an `agent_instruction` row.

An agent running with `--dangerously-skip-permissions` in its process flags is operating in a mode where it won't ask the user before executing code or writing files. That runtime posture shows up as `skip_permissions_runtime` in `risk_flags` and the process is live in `running = '1'`.

---

## What it deliberately won't do

The extension is detection-only. It reads, parses, and hashes. It does not execute discovered binaries to check versions. It does not connect to MCP servers to enumerate their live tool catalog. It does not read environment variable values (only names). It does not write anything to disk.

That constraint matters operationally: if you're running this as root via fleetd on production endpoints, "detection-only" is not a marketing qualifier — it's the guarantee that the extension itself won't become an attack surface.

---

## Get it

Repo: [github.com/karmine05/agentic-detector](https://github.com/karmine05/agentic-detector)

The repo is public. Prebuilt binaries for macOS (universal), Linux (amd64), and Windows (amd64) are attached to the [v0.2.0 release](https://github.com/karmine05/agentic-detector/releases/tag/v0.2.0) with SHA256SUMS for integrity verification.

Build from source: `make build-all` produces Fleet-named binaries in `./build/`. The extension is written in Go, passes `govulncheck` and `gosec` clean, and uses a pinned toolchain (`go 1.26.4`).

If you find false positives, missing tools, or gap in the knowledge base — open an issue or a PR. The classification KB is a JSON file; adding a new MCP server or agent CLI is a small diff.
