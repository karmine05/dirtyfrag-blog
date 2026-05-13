---
title: "Endpoint Risk and Threat Hunting, in Plain English: A Fleet MCP Manifesto"
date: 2026-05-13T09:00:00-04:00
draft: false
tags: ["fleet", "mcp", "osquery", "ai", "threat-hunting", "detection-engineering", "security-ops"]
categories: ["security-ops"]
description: "Why fleet-mcp exists. A manifesto for natural-language endpoint security: ask a question in English, get a real osquery scan across every host you own, with the SQL shown to you and the assumptions named."
summary: "Endpoint risk and threat hunting with Fleet just got a lot easier with the MCP. fleet-mcp is a Model Context Protocol server that turns Fleet's API into a typed tool catalog any AI agent can call. This is the manifesto — why it exists, what it does, what it deliberately won't do, and what it gives you that a REST API never could."
cover:
  hidden: true
ShowToc: true
TocOpen: false
ShowReadingTime: true
ShowWordCount: true
---

> **The pitch in one sentence:** endpoint risk and threat hunting with Fleet just got a lot easier with the MCP. Ask a question in English. Get a real osquery scan across every host you own. See the SQL. See the assumptions. Decide what to do next.

| | |
|---|---|
| **What it is** | A Model Context Protocol server for Fleet — exposes Fleet's API as typed tools any AI agent can call |
| **Where it runs** | Anywhere with stdio or SSE — Claude Desktop, Claude Code, Cursor, Slack bots, custom agents |
| **What it gives you** | Live osquery, policy compliance, CVE impact, fleet inventory — spoken to in plain English |
| **What it doesn't do** | Hide its work, run destructive ops on its own authority, or pretend to be a vulnerability scanner |
| **Repo** | [github.com/karmine05/fleet-mcp](https://github.com/karmine05/fleet-mcp) |

---

## The thirty-second pitch

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 360" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="Before and after: REST API vs natural language">
  <style>
    .panel { fill: none; stroke: currentColor; stroke-opacity: 0.25; stroke-width: 1.5; rx: 8; }
    .panel-title { font: 600 14px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .body { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; fill: currentColor; }
    .chat { font: 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .muted { fill: currentColor; fill-opacity: 0.55; }
    .accent { fill: #6366f1; }
    .arrow { stroke: currentColor; stroke-opacity: 0.4; stroke-width: 1.5; fill: none; }
    .label-pill { fill: currentColor; fill-opacity: 0.08; rx: 12; }
  </style>

  <rect class="label-pill" x="20" y="14" width="80" height="22"/>
  <text x="60" y="29" text-anchor="middle" class="chat muted">BEFORE</text>

  <rect class="panel" x="20" y="50" width="360" height="280" rx="8"/>
  <text x="40" y="78" class="panel-title">REST API + jq</text>
  <text x="40" y="110" class="body">$ curl -H "Authorization: Bearer $FLEET" \</text>
  <text x="40" y="128" class="body">    "$URL/api/v1/fleet/queries" | \</text>
  <text x="40" y="146" class="body">    jq '.queries[] | select(.platform</text>
  <text x="40" y="164" class="body">    == "linux")'</text>
  <text x="40" y="194" class="body muted"># pick a query, get its id...</text>
  <text x="40" y="212" class="body">$ curl -X POST -d @body.json \</text>
  <text x="40" y="230" class="body">    "$URL/api/v1/fleet/queries/run"</text>
  <text x="40" y="260" class="body muted"># poll for results, parse JSON,</text>
  <text x="40" y="278" class="body muted"># cross-reference host IDs to</text>
  <text x="40" y="296" class="body muted"># labels, build the report yourself</text>
  <text x="40" y="320" class="body" fill="#ef4444"># 15 minutes later: answer</text>

  <path class="arrow" d="M 395 190 L 420 190" marker-end="url(#arr)"/>
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" fill-opacity="0.4"/>
    </marker>
  </defs>

  <rect class="label-pill" x="430" y="14" width="80" height="22"/>
  <text x="470" y="29" text-anchor="middle" class="chat muted">AFTER</text>

  <rect class="panel" x="430" y="50" width="350" height="280" rx="8"/>
  <text x="450" y="78" class="panel-title">Plain English</text>

  <rect x="450" y="100" width="310" height="48" rx="6" fill="currentColor" fill-opacity="0.06"/>
  <circle cx="468" cy="124" r="8" class="accent"/>
  <text x="486" y="121" class="chat">you</text>
  <text x="486" y="139" class="chat muted">how many linux hosts haven't rebooted in 30 days?</text>

  <rect x="450" y="160" width="310" height="100" rx="6" fill="currentColor" fill-opacity="0.06"/>
  <circle cx="468" cy="184" r="8" fill="#10b981"/>
  <text x="486" y="181" class="chat">fleet-mcp</text>
  <text x="486" y="199" class="chat muted">scanning 7 linux hosts across 3 teams...</text>
  <text x="486" y="220" class="chat">2 hosts: uptime &gt; 500d, both servers.</text>
  <text x="486" y="238" class="chat">3 hosts &lt; 30d. 2 offline.</text>
  <text x="486" y="256" class="chat muted">SQL used: SELECT * FROM uptime; (shown ↓)</text>

  <text x="450" y="290" class="chat" fill="#10b981">✓ 30 seconds. SQL visible. Receipts attached.</text>
  <text x="450" y="312" class="chat muted">Same osquery. Same Fleet API. Different surface.</text>
</svg>
</div>

That's the entire idea. Same Fleet. Same osquery. Same authoritative data. The interface changed from *plumbing* to *language*, and the time-to-answer collapsed by an order of magnitude. The osquery, the Fleet RBAC, the policies — none of that goes away. The 15 minutes of curl-jq-pagination glue does.

---

## Why MCP exists

Fleet already had an excellent REST API. osquery already had a beautiful SQL surface. So why build another thing in front of them?

Because the gap that actually costs you time isn't between *the question* and *the data*. The data is right there. The gap is between *the question* and *the right query against the right hosts presented in a form a human can act on in five minutes*.

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 200" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="The gap between a question and an answer">
  <style>
    .node { fill: currentColor; fill-opacity: 0.06; stroke: currentColor; stroke-opacity: 0.3; stroke-width: 1.5; }
    .node-label { font: 600 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; text-anchor: middle; }
    .gap { font: 600 12px ui-sans-serif, system-ui, sans-serif; fill: #ef4444; text-anchor: middle; }
    .arr { stroke: currentColor; stroke-opacity: 0.4; stroke-width: 2; fill: none; }
  </style>
  <defs>
    <marker id="a2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" fill-opacity="0.5"/>
    </marker>
  </defs>

  <rect class="node" x="20" y="60" width="130" height="60" rx="8"/>
  <text x="85" y="86" class="node-label">A question</text>
  <text x="85" y="104" class="node-label" font-weight="400" fill-opacity="0.7">"are we exposed?"</text>

  <path class="arr" d="M 155 90 L 235 90" marker-end="url(#a2)"/>
  <text x="195" y="78" class="gap">↑ the gap</text>

  <rect class="node" x="240" y="60" width="160" height="60" rx="8"/>
  <text x="320" y="86" class="node-label">The right query</text>
  <text x="320" y="104" class="node-label" font-weight="400" fill-opacity="0.7">SQL · targets · schema</text>

  <path class="arr" d="M 405 90 L 485 90" marker-end="url(#a2)"/>

  <rect class="node" x="490" y="60" width="140" height="60" rx="8"/>
  <text x="560" y="86" class="node-label">Live results</text>
  <text x="560" y="104" class="node-label" font-weight="400" fill-opacity="0.7">per host, per team</text>

  <path class="arr" d="M 635 90 L 715 90" marker-end="url(#a2)"/>

  <rect class="node" x="660" y="60" width="120" height="60" rx="8"/>
  <text x="720" y="86" class="node-label">A decision</text>
  <text x="720" y="104" class="node-label" font-weight="400" fill-opacity="0.7">action or no-op</text>

  <text x="400" y="160" class="gap" font-size="13">The bridge that used to be hand-built API glue. That's what fleet-mcp is.</text>
</svg>
</div>

The reason that gap is expensive is that crossing it well requires knowing:

- Which osquery tables exist on which platforms (the `chrome_extensions` table behaves differently on macOS vs Linux; `kernel_modules` only exists on Linux).
- Which Fleet labels and teams a question should be scoped to.
- How to validate the target set before firing a fleet-wide query that gets rate-limited or returns garbage.
- How to format results so the conclusion is obvious, not buried in twelve columns of host JSON.

A human security engineer who's been doing this for years can do all of that in their head. Anyone newer to the platform — or any AI agent without context — can't. fleet-mcp encodes that knowledge as **typed tools**, so the agent doing the work has the same situational awareness an experienced operator would.

---

## What fleet-mcp actually is

A small Go server. Two transports (stdio and SSE). One job: turn Fleet's REST surface into a catalog of typed tools that obey the Model Context Protocol, so any MCP-compatible AI client — Claude Desktop, Claude Code, Cursor, or a custom Slack bot — can call them natively without re-implementing Fleet's API for the nth time.

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 380" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="fleet-mcp architecture">
  <style>
    .lane { fill: currentColor; fill-opacity: 0.04; stroke: currentColor; stroke-opacity: 0.2; }
    .lane-title { font: 700 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; fill-opacity: 0.7; letter-spacing: 0.04em; }
    .box { fill: currentColor; fill-opacity: 0.08; stroke: currentColor; stroke-opacity: 0.35; stroke-width: 1.5; }
    .box-mcp { fill: #6366f1; fill-opacity: 0.15; stroke: #6366f1; stroke-opacity: 0.8; stroke-width: 2; }
    .label { font: 600 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; text-anchor: middle; }
    .sub { font: 11px ui-sans-serif, system-ui, sans-serif; fill: currentColor; fill-opacity: 0.65; text-anchor: middle; }
    .arr { stroke: currentColor; stroke-opacity: 0.45; stroke-width: 2; fill: none; }
    .arr-label { font: 600 11px ui-monospace, monospace; fill: currentColor; fill-opacity: 0.75; text-anchor: middle; }
  </style>
  <defs>
    <marker id="a3" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" fill-opacity="0.55"/>
    </marker>
  </defs>

  <rect class="lane" x="10" y="20" width="180" height="340" rx="10"/>
  <text x="100" y="42" text-anchor="middle" class="lane-title">AI CLIENT</text>
  <rect class="box" x="30" y="70" width="140" height="44" rx="6"/>
  <text x="100" y="96" class="label">Claude Desktop</text>
  <rect class="box" x="30" y="128" width="140" height="44" rx="6"/>
  <text x="100" y="154" class="label">Cursor / Claude Code</text>
  <rect class="box" x="30" y="186" width="140" height="44" rx="6"/>
  <text x="100" y="212" class="label">Slack bot</text>
  <rect class="box" x="30" y="244" width="140" height="44" rx="6"/>
  <text x="100" y="270" class="label">Custom agent</text>
  <text x="100" y="320" class="sub">whichever surface</text>
  <text x="100" y="336" class="sub">your team lives in</text>

  <path class="arr" d="M 195 200 L 245 200" marker-end="url(#a3)"/>
  <text x="220" y="190" class="arr-label">MCP</text>

  <rect class="lane" x="250" y="20" width="220" height="340" rx="10"/>
  <text x="360" y="42" text-anchor="middle" class="lane-title">fleet-mcp</text>
  <rect class="box-mcp" x="270" y="70" width="180" height="270" rx="8"/>
  <text x="360" y="96" class="label">Tool catalog</text>
  <text x="360" y="120" class="sub">get_endpoints · get_host</text>
  <text x="360" y="138" class="sub">get_policies · get_labels</text>
  <text x="360" y="156" class="sub">get_vulnerability_impact</text>
  <text x="360" y="174" class="sub">prepare_live_query</text>
  <text x="360" y="192" class="sub">run_live_query</text>
  <text x="360" y="210" class="sub">get_osquery_schema</text>
  <text x="360" y="228" class="sub">get_vetted_queries</text>
  <text x="360" y="246" class="sub">get_aggregate_platforms</text>
  <text x="360" y="264" class="sub">…</text>
  <text x="360" y="296" class="label" font-size="11" fill-opacity="0.7">stdio · SSE</text>
  <text x="360" y="312" class="sub">Go binary, MIT</text>

  <path class="arr" d="M 475 200 L 525 200" marker-end="url(#a3)"/>
  <text x="500" y="190" class="arr-label">REST</text>

  <rect class="lane" x="530" y="20" width="260" height="340" rx="10"/>
  <text x="660" y="42" text-anchor="middle" class="lane-title">FLEET + OSQUERY</text>
  <rect class="box" x="555" y="70" width="210" height="44" rx="6"/>
  <text x="660" y="96" class="label">Fleet API</text>
  <text x="660" y="108" class="sub" font-size="10">RBAC · audit · scheduling</text>
  <rect class="box" x="555" y="130" width="210" height="44" rx="6"/>
  <text x="660" y="156" class="label">osquery agents</text>
  <text x="660" y="168" class="sub" font-size="10">on every enrolled host</text>

  <rect class="box" x="555" y="200" width="60" height="50" rx="6"/>
  <text x="585" y="222" class="label" font-size="11">Linux</text>
  <text x="585" y="238" class="sub" font-size="10">workstation</text>
  <rect class="box" x="630" y="200" width="60" height="50" rx="6"/>
  <text x="660" y="222" class="label" font-size="11">macOS</text>
  <text x="660" y="238" class="sub" font-size="10">workstation</text>
  <rect class="box" x="705" y="200" width="60" height="50" rx="6"/>
  <text x="735" y="222" class="label" font-size="11">Windows</text>
  <text x="735" y="238" class="sub" font-size="10">workstation</text>

  <rect class="box" x="555" y="266" width="100" height="50" rx="6"/>
  <text x="605" y="288" class="label" font-size="11">IT servers</text>
  <text x="605" y="304" class="sub" font-size="10">long-uptime cohort</text>
  <rect class="box" x="665" y="266" width="100" height="50" rx="6"/>
  <text x="715" y="288" class="label" font-size="11">Testing &amp; QA</text>
  <text x="715" y="304" class="sub" font-size="10">VMs, lab hosts</text>
</svg>
</div>

What the agent gets from the tool catalog isn't access to a generic HTTP client — it's a set of **purpose-built primitives** with names that map to questions an operator would ask. `get_vulnerability_impact(cve_id)`. `get_policy_compliance(policy_id)`. `prepare_live_query` → `run_live_query` (the prepare step exists specifically to validate target sets and schema *before* a destructive-looking SQL hits production).

The full inventory at the time of writing:

| Tool | What it does |
|---|---|
| `get_endpoints` | List enrolled hosts |
| `get_host` | Full host detail — labels, team, platform |
| `get_queries` | List saved Fleet queries |
| `get_policies` | List policies with pass/fail counts |
| `get_labels` | List labels |
| `get_aggregate_platforms` | Host count broken down by OS |
| `get_total_system_count` | Active enrolled count |
| `get_policy_compliance` | Compliance stats for a policy |
| `get_vulnerability_impact` | Systems impacted by a CVE |
| `prepare_live_query` | Validate targets + fetch osquery schema |
| `run_live_query` | Execute live osquery SQL |
| `create_saved_query` | Persist a new query |
| `get_osquery_schema` | Schema for a given platform |
| `get_vetted_queries` | CIS-8.1 compliance query library |

Two patterns to notice. First, the `prepare → run` split for live queries is not bureaucracy — it's the safety rail that keeps an agent from firing a malformed SQL against 10,000 hosts because it hallucinated a table name. Second, `get_vetted_queries` ships a curated library so the agent has good defaults instead of inventing osquery from first principles every time.

---

## Three things this changes about endpoint risk and threat hunting

The abstractions above only matter if they translate into work you couldn't easily do before. Three real examples — sanitized — from running this in production.

### 1. Pre-CVE response, in minutes

Public exploit drops. No CVE assigned. Vendor advisories not out yet. Your vulnerability scanner returns empty because there's nothing to match.

Drop the intel blurb into Slack. Tag the bot. The bot translates the artifacts in the writeup (kernel modules, sockets, sysctls, distro families) into an osquery scan, runs `prepare_live_query` to validate targets, then `run_live_query` against every Linux host across every team — and returns a per-host artifact report with named risks.

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 470" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="Sanitized Slack thread example">
  <style>
    .frame { fill: currentColor; fill-opacity: 0.04; stroke: currentColor; stroke-opacity: 0.25; stroke-width: 1.5; rx: 8; }
    .msg { fill: currentColor; fill-opacity: 0.07; rx: 6; }
    .name { font: 700 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .ts { font: 11px ui-sans-serif, system-ui, sans-serif; fill: currentColor; fill-opacity: 0.55; }
    .body { font: 12.5px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .mono { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; fill: currentColor; }
    .muted { fill: currentColor; fill-opacity: 0.65; }
    .pill { fill: #6366f1; fill-opacity: 0.2; rx: 4; }
    .ok { fill: #10b981; }
    .bad { fill: #ef4444; }
  </style>

  <rect class="frame" x="10" y="10" width="780" height="450" rx="10"/>

  <circle cx="40" cy="50" r="14" fill="#6366f1" fill-opacity="0.6"/>
  <text x="65" y="46" class="name">operator</text>
  <text x="138" y="46" class="ts">12:27 PM</text>
  <rect class="msg" x="65" y="56" width="710" height="62"/>
  <text x="80" y="78" class="body">@Fleet — public Linux PrivEsc PoC just dropped, no CVE yet.</text>
  <text x="80" y="98" class="body muted">Affects Ubuntu / RHEL / Fedora. Two variants chain page-cache writes. Run a targeted scan</text>
  <text x="80" y="114" class="body muted">across all teams, surface the at-risk hosts and the kernel module state. Artifacts only.</text>

  <circle cx="40" cy="148" r="14" fill="#10b981" fill-opacity="0.6"/>
  <text x="65" y="144" class="name">Fleet</text>
  <text x="100" y="144" class="ts">12:27 PM · used 3 tools</text>

  <rect class="pill" x="65" y="156" width="160" height="20"/>
  <text x="75" y="170" class="mono">prepare_live_query</text>
  <rect class="pill" x="232" y="156" width="160" height="20"/>
  <text x="242" y="170" class="mono">get_osquery_schema</text>
  <rect class="pill" x="399" y="156" width="130" height="20"/>
  <text x="409" y="170" class="mono">run_live_query</text>

  <rect class="msg" x="65" y="186" width="710" height="260"/>
  <text x="80" y="208" class="body">Scope: 7 Linux hosts across 3 teams. 3 online, 4 offline (queued for re-run).</text>

  <text x="80" y="240" class="body">Per-host artifacts (online)</text>
  <text x="92" y="262" class="mono">host-a · workstation · ubuntu 24.04 · kernel 6.18.7  </text>
  <text x="92" y="278" class="body">  modules of interest: xfrm_user <tspan class="ok">✓</tspan>  xfrm_algo <tspan class="ok">✓</tspan>  rxrpc <tspan class="bad">not loaded</tspan></text>
  <text x="92" y="294" class="body muted">  risk: distro in scope; absence from lsmod ≠ mitigation (auto-load on socket open)</text>

  <text x="92" y="320" class="mono">host-b · IT servers · ubuntu 24.04 · kernel 6.8.0 · uptime 503d</text>
  <text x="92" y="336" class="body muted">  risk: vulnerable kernel range, hasn't rebooted in ~1.4y — schedule maintenance</text>

  <text x="92" y="362" class="mono">host-c · IT servers · fedora 41 · kernel 6.11.4 · uptime 504d</text>
  <text x="92" y="378" class="body muted">  risk: explicitly named distro, same reboot concern</text>

  <text x="80" y="408" class="body">Next actions (say the word and I'll draft a Fleet policy PR):</text>
  <text x="92" y="424" class="body muted">  1. Policy: fail any host with uptime &gt; 30d  &nbsp; 2. kernel.unprivileged_userns_clone=0</text>
  <text x="92" y="440" class="body muted">  3. modprobe blacklist rxrpc / xfrm on workstations  &nbsp; 4. re-scan 4 offline hosts on return</text>
</svg>
</div>

The artifacts that matter — kernel version, loaded modules, uptime, distro family — are the artifacts the agent surfaces. The host names are placeholders. The risks are named. The next actions are concrete. **No CVE was harmed in the making of this answer.**

### 2. CVE blast radius, scoped to a team

A different shape: a CVE *does* exist (or four — Chrome zero-days are like that), and the right question is "how many of my systems are exposed *and* which team are they on, because the answer determines who I message."

The classic version of this is a JIRA ticket, a curl loop, a spreadsheet, and 90 minutes. With the MCP it's three sentences:

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 280" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="CVE blast radius example">
  <style>
    .frame { fill: currentColor; fill-opacity: 0.04; stroke: currentColor; stroke-opacity: 0.25; stroke-width: 1.5; rx: 8; }
    .msg { fill: currentColor; fill-opacity: 0.07; rx: 6; }
    .name { font: 700 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .body { font: 12.5px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .mono { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; fill: currentColor; }
    .muted { fill: currentColor; fill-opacity: 0.7; }
    .num { font: 700 18px ui-sans-serif, system-ui, sans-serif; fill: #ef4444; }
  </style>

  <rect class="frame" x="10" y="10" width="780" height="260" rx="10"/>

  <circle cx="40" cy="44" r="12" fill="#6366f1" fill-opacity="0.6"/>
  <text x="60" y="48" class="body">how many systems have the latest Chrome vulnerabilities — and how many on the Workstations team?</text>

  <circle cx="40" cy="92" r="12" fill="#10b981" fill-opacity="0.6"/>
  <text x="60" y="84" class="name">Fleet</text>
  <text x="60" y="104" class="body muted">tools: web_search → get_vulnerability_impact ×4 → get_endpoints(fleet=Workstations) → run_live_query</text>

  <rect class="msg" x="60" y="118" width="710" height="140"/>
  <text x="78" y="140" class="body">Latest Chrome zero-days across the fleet (157 hosts total):</text>

  <text x="78" y="168" class="num">12</text>
  <text x="120" y="168" class="body">CVE-XXXX-A (WebGPU UAF) · CISA KEV deadline today</text>

  <text x="78" y="190" class="num">10</text>
  <text x="120" y="190" class="body">on the <tspan font-weight="600">Workstations</tspan> team — running Chrome &lt; 146.0.7680.178</text>

  <text x="78" y="212" class="body muted">  Plus 1 host with a stale Chrome-for-Testing build; 1 host on Chrome Canary.</text>
  <text x="78" y="230" class="body muted">  54 hosts offline at scan — actual impacted count may be higher. Re-running on roll-in.</text>

  <text x="78" y="252" class="body">SQL used: <tspan class="mono">SELECT name, bundle_short_version FROM apps WHERE name LIKE '%Chrome%';</tspan></text>
</svg>
</div>

Three properties that matter here:

1. **It scopes to a team.** That's a `get_endpoints(fleet=Workstations)` call under the hood, not a SQL filter the operator had to write.
2. **It chains four CVE lookups in one breath.** Each `get_vulnerability_impact` is cheap, so the agent runs them in parallel and merges. A human doing this by hand would short-circuit and only check one.
3. **It surfaces the offline cohort honestly.** "54 hosts offline at scan" is a real caveat, not a footnote you have to hunt for. The answer is bounded, and the bound is shown.

### 3. Knowing what *not* to do

The most underrated property of a tool catalog is what's *not* in it. The MCP doesn't expose `read_keychain_secret`. It can't. macOS keychain values are encrypted at rest, and Fleet can read metadata via osquery but not secrets.

When asked "what's in my keychain?" the right answer is the one the agent actually gives:

<div style="margin: 1.5em 0;">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 200" width="100%" style="max-width: 800px; height: auto;" role="img" aria-label="Bounded inspection example">
  <style>
    .frame { fill: currentColor; fill-opacity: 0.04; stroke: currentColor; stroke-opacity: 0.25; stroke-width: 1.5; rx: 8; }
    .msg { fill: currentColor; fill-opacity: 0.07; rx: 6; }
    .body { font: 12.5px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
    .muted { fill: currentColor; fill-opacity: 0.7; }
    .name { font: 700 13px ui-sans-serif, system-ui, sans-serif; fill: currentColor; }
  </style>
  <rect class="frame" x="10" y="10" width="780" height="180" rx="10"/>

  <circle cx="40" cy="44" r="12" fill="#6366f1" fill-opacity="0.6"/>
  <text x="60" y="48" class="body">what's in the keychain on user-a's MacBook?</text>

  <circle cx="40" cy="92" r="12" fill="#10b981" fill-opacity="0.6"/>
  <text x="60" y="84" class="name">Fleet</text>
  <rect class="msg" x="60" y="100" width="710" height="80"/>
  <text x="78" y="124" class="body">I can't access keychain values. Secrets are encrypted by macOS; even with admin osquery,</text>
  <text x="78" y="142" class="body">passwords and private keys aren't readable. I <tspan font-weight="600">can</tspan> show metadata — labels, types, paths,</text>
  <text x="78" y="160" class="body">creation dates — if that's useful. Want me to run that scoped to user-a's host?</text>
</svg>
</div>

This is the boring, correct behavior, and it's the one you want. An MCP server that pretended to do more than its underlying API allows would be worse than no MCP server at all. The discipline is in the tool boundary, not in the prompt.

---

## What this is not

A manifesto without a list of what it isn't is just marketing.

**fleet-mcp is not a vulnerability scanner.** It's a translation layer for endpoint *questions*. The authoritative data still lives in osquery and Fleet. When the CVE pipeline has a row, the MCP can pull it via `get_vulnerability_impact`. When the pipeline doesn't have a row yet — Dirty Frag, the Mini Shai-Hulud worm, the npm supply-chain compromise of the week — the MCP runs the artifact query the operator described and tells you what the hosts actually look like. **Catalog tools answer "what CVEs apply?" Artifact tools answer "what do these hosts actually look like right now?" The second one is what threat hunting needs.**

**fleet-mcp is not an autonomous incident responder.** The architecture is deliberate: the agent can *propose* a Fleet policy, a script, a query — but the human stays in the loop for anything that mutates state. `run_live_query` runs read-only osquery. There is no `delete_host` tool. There is no `run_arbitrary_shell`. If you want to wire the same MCP into a workflow that *does* run scripts, that's downstream — and you should keep the approval gate.

**fleet-mcp doesn't hide its SQL.** Every example above ships with the underlying osquery shown. This is non-negotiable. If you can't review the query, you can't trust the answer, and the moment trust breaks the tool stops being useful. The transparency isn't decorative — it's the contract.

**fleet-mcp is not a substitute for knowing your stack.** The agent will happily run a query that asks `kernel_modules` to do work on a macOS host, and Fleet will return nothing, and the operator has to know enough to recognize that. The tools encode structure; they don't replace literacy.

---

## How to try it

Half a page. From a fresh clone:

```bash
git clone https://github.com/karmine05/fleet-mcp.git
cd fleet-mcp
cp .env.example .env
# edit .env with your Fleet base URL + API token
go build -o fleet-mcp .
./fleet-mcp              # SSE on :8080/sse for Cursor / Claude Code
# or
./fleet-mcp -transport stdio   # for Claude Desktop
```

For Claude Desktop, drop this into `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fleet": {
      "command": "/path/to/fleet-mcp",
      "args": ["-transport", "stdio"],
      "env": {
        "FLEET_BASE_URL": "https://your-fleet.example.com",
        "FLEET_API_KEY": "YOUR_FLEET_API_KEY"
      }
    }
  }
}
```

Restart Claude. The Fleet tools show up in context. Ask it something hard. Watch the SQL.

---

## The framing that holds up

Two questions sit at the heart of every endpoint security workflow:

> *Which hosts are exposed right now?*
> *What did we miss?*

For a long time both were answered the same way: ship a vulnerability scanner, hope the catalog is current, page through a dashboard, write a spreadsheet. The catalog is never quite current and the spreadsheet is always slightly stale. The answers were technically correct and operationally inert.

The other path — and the one fleet-mcp commits to — is to keep the authoritative data (osquery, Fleet, RBAC) exactly where it is, expose it as a typed tool surface, and let the language model be the thing that translates a tired security engineer's 11pm question into the right scan against the right hosts presented in the right form.

The data was already there. The plumbing is what changed. Endpoint risk and threat hunting with Fleet just got a lot easier with the MCP.

---

## Links

- **Repo:** [github.com/karmine05/fleet-mcp](https://github.com/karmine05/fleet-mcp)
- **Model Context Protocol:** [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Fleet:** [fleetdm.com](https://fleetdm.com/)
- **Demo (1-hour walkthrough):** [youtube.com/watch?v=8K77litllPk](https://www.youtube.com/watch?v=8K77litllPk)

License: MIT.
