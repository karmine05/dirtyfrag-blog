---
canonical: "https://karmine05.github.io/dirtyfrag-blog/posts/fleet-kever-agent-upgrade-runbook/"
meta-article:modified_time: "2026-09-27T14:00:00-04:00"
meta-article:published_time: "2026-09-27T14:00:00-04:00"
meta-article:section: posts
meta-article:tag: Security-Ops
meta-author: Dhruv Majumdar
meta-description: "A local AI agent drives a Fleet upgrade and a kernel KEV mitigation wave over MCP. One honest osquery later, 24 of 25 noble hosts were verified running the patched kernel from memory, not from the package database, and the two KEVs with no fix yet sat in a watchlist with a written closure condition instead of a green column."
meta-keywords: fleet,fleet-mcp,osquery,kev,kernel,linux,local-llm,vllm,vulnerability-management,security-ops,incident-response,runbook,reboot
meta-og:description: "A local AI agent drives a Fleet upgrade and a kernel KEV mitigation wave over MCP. Installed versus running is the whole story: the reboot is the mitigation, the kernel in memory is the evidence, and the open KEVs stay in a watchlist until the USN lands."
meta-og:locale: en
meta-og:site_name: "karmine's notes"
meta-og:title: "One Agent, One Fleet, One Reboot: Upgrading and Mitigating a Kernel KEV Wave with Fleet, MCP, and Local AI"
meta-og:type: article
meta-og:url: "https://karmine05.github.io/dirtyfrag-blog/posts/fleet-kever-agent-upgrade-runbook/"
meta-title: "One Agent, One Fleet, One Reboot: Fleet, MCP, and Local AI against a Kernel KEV Wave · karmine's notes"
meta-twitter:card: summary
meta-twitter:description: "Installed is not running. The reboot is the mitigation and the kernel in memory is the evidence. A local LLM, fleet-mcp, and one osquery turn a double problem into a verified runbook."
meta-twitter:title: "One Agent, One Fleet, One Reboot: Fleet, MCP, and Local AI against a Kernel KEV Wave"
title: "One Agent, One Fleet, One Reboot: Upgrading and Mitigating a Kernel KEV Wave with Fleet, MCP, and Local AI"
slug: fleet-kever-agent-upgrade-runbook
date: "2026-09-27T14:00:00-04:00"
categories:
  - Security-Ops
tags:
  - Fleet
  - Fleet-MCP
  - Osquery
  - KEV
  - Linux
  - Kernel
  - AI
  - Local-LLM
  - Vulnerability-Management
  - Security-Ops
  - Incident-Response
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

> **One sentence:** a local AI agent, a Model Context Protocol bridge to Fleet, and one honest query later, 24 Linux hosts were upgraded, rebooted, verified, and the two kernel KEVs that still have no fix sat in a watchlist instead of a "patched" column.

| | |
|---|---|
| **Fleet server** | 4.91.1 to 4.92.1, live at 192.168.89.92, migrations applied, zero restarts |
| **fleetctl** | 4.90.0 to 4.92.1, checksummed on the macOS control box |
| **Fleet in scope** | 35 hosts: 25 linux, 8 windows, 2 macos |
| **Kernel wave** | 24 of 25 noble hosts verified running `6.8.0-142-generic` from the running kernel, not the package database |
| **Open items** | 2 kernel KEVs with no noble fix yet, tracked in a watchlist until the USN lands |
| **Brain doing the work** | A local vLLM endpoint, 4x A6000, running the whole session on-box |

## The shape of the job

Every few weeks the lab gets a double problem at once: a new Fleet release, and new kernel bugs in the CISA Known Exploited Vulnerabilities catalog that the fleet is running. Doing both by hand means checking the GitHub release, downloading, checksumming, stopping the service, swapping the binary, running migrations, starting it back up, and then separately figuring out which of thirty-five hosts run the vulnerable kernel versus which ones just *have the patch package installed*.

That second part is the part that lies to you. `dpkg` will happily say a kernel package is installed while the machine is still running the old one in memory. A reboot is what turns an install into a mitigation. Any vulnerability report that does not separate *installed* from *running* is reporting hope, not state.

This post is the runbook for exactly that double problem, executed by an AI agent over MCP instead of by a human over SSH. The agent is the hands, Fleet is the substrate, and the only thing a human had to do was say "go".

## The stack, in one picture

{{< figure src="images/architecture.svg" alt="The upgrade stack: a local vLLM agent inside its harness (skills, memory, secrets vault, terminal) calls fleet-mcp tools over TLS to a Fleet 4.92.1 server that reaches 35 hosts" caption="The stack that did this work. The harness holds the runbooks and the gotchas; fleet-mcp holds the typed tools; Fleet holds the source of truth. No component is in the cloud." >}}

Four things make the difference versus doing this by hand:

1. **Local AI.** The brain is a vLLM endpoint on the lab network (the `automater` box, 4x A6000). No prompt leaves the network, no per-token billing, and the session that wrote this upgrade ran end-to-end on-box. Local inference is slow enough that you plan in bigger steps, fast enough that "query all 25 hosts" is a one-line ask.
2. **fleet-mcp.** Fleet's API is exposed as typed tools. The agent does not parse REST and jq. It calls `run_live_query` with a scope and SQL, and gets results keyed to host names.
3. **The harness.** Skills are saved runbooks (the exact Fleet upgrade procedure, with the gotchas), memory holds durable facts (server address, which hosts are out of scope, prior version pins), and secrets never pass through the conversation. The agent is opinionated about *order*: check, verify, then act, and only on a green light.
4. **Fleet itself** as the source of truth for what is installed versus what is running.

## Part 1: the Fleet 4.92.1 upgrade

The upgrade follows the exact same sequence every time, which is why it exists as a skill rather than tribal knowledge.

1. **Query the release first.** `GET /repos/fleetdm/fleet/releases/latest` returns the tag and every asset name. Download the tarball *and* the release's own `checksums.txt`, and verify the exact tarball line before touching anything. The release tag carries a `fleet-` prefix (`fleet-v4.92.1`, not `v4.92.1`), and guessing either one burns you.
2. **Stop Fleet.** The systemd drop-in on nginx (`Requires=fleetdm.service`) means stopping Fleet also stops nginx, and TLS `:443` drops for every client. That is expected. You will start both at the end.
3. **Swap the binary while stopped**, with a version-suffixed backup. Overwriting a running binary fails with "Text file busy", which is the only reason the stop has to come first.
4. **Run `fleet prepare db`** as the app user. On a multi-minor jump this applies a dozen or more migrations and finishes in seconds. The literal string `Migrations completed.` is the signal. Skip this step and the new binary crash-loops with "Your Fleet database is missing required migrations."
5. **Start Fleet, then nginx**, and verify the port that actually matters: 8080 must be *listening*. `systemctl is-active` can say `active` while the process is stuck in a MySQL retry loop and never binds.

This run, the numbers: Fleet 4.91.1 to 4.92.1 on the server, fleetctl 4.90.0 to 4.92.1 on the control box, both checksums `OK`, migrations `100% complete`, `fleet version` reporting 4.92.1, `NRestarts=0`, and a post-upgrade query through nginx TLS returning the same 35-host baseline as before the stop. The transient 401s in the journal were the old session keys expiring, not a problem.

The whole upgrade was about ten minutes of agent time including the download and both checksum verifications. The part that is not in the binary is the part that saves time: knowing step 4 is mandatory and knowing nginx will not start itself.

## Part 2: the kernel KEV wave

Two entries in the CISA KEV catalog (catalog 2026.09.25, 1726 entries) matter for this fleet. Both are Linux kernel, and both carry the same standing instruction: apply the vendor's mitigations until a fix ships.

| CVE | Added | Description | Why it stays open |
|---|---|---|---|
| CVE-2026-53362 | 2026-08-27 | Privilege escalation via the IPv6 networking subsystem | No noble fix out yet; vendor-instructed mitigations apply |
| CVE-2026-53266 | 2026-09-18 | Out-of-bounds write in the ebtables SNAT target (CWE-787) | No noble fix out yet; vendor-instructed mitigations apply |

The rule this lab runs on: **open by ceiling, close when the USN lands.** The hosts are upgraded to the newest kernel in the noble pocket at the moment the wave is processed (6.8.0-142, i.e. `-142.142` on this host, with older point releases still present in the dpkg database), the reboots are forced so the new kernel is the one in memory, and the two KEVs are tracked as *mitigated-by-ceiling, pending vendor fix* instead of being force-marked patched. Marking them closed before the USN exists is how a "green" dashboard becomes a false sense of safety.

### Verification: running kernel, not installed package

The query that proves the wave landed reads the kernel the host is actually executing, then the uptime that proves it booted recently:

```sql
SELECT k.version AS running_kernel,
       u.total_seconds AS uptime_seconds
FROM kernel_info k, uptime u
```

Run across all 25 Linux hosts in one `run_live_query`, with 25 of 25 responding:

{{< figure src="images/kernel-wave.svg" alt="Live kernel verification result: 24 of 25 Linux hosts running 6.8.0-142-generic with uptimes of about 23.6 hours, ad-guard-home running the Proxmox guest kernel 5.15.158-2-pve as the single scoped-out outlier" caption="One run_live_query, 25 of 25 hosts responded. Uptimes clustered at ~23.6h are the reboot proof; automater at ~4 days sits in the queue on purpose. The LXC outlier is hypervisor-scoped, not a miss." >}}

Two details in that figure carry the whole verification:

- **Uptime is the reboot proof.** A host can have the `-142` package and still be running `-139` from three months ago. Uptimes clustered around 23.6 hours on all 24 hosts mean the reboots happened and the new kernel is the one answering. The one outlier, `automater` at ~4 days, is the vLLM box: it got the new kernel on its last *natural* reboot and stays on the reboot queue until the maintenance window, which is a deliberate trade, not a miss.
- **The 25th host is not a failure.** `ad-guard-home` is a Proxmox LXC container. It runs the PVE guest kernel `5.15.158-2-pve`, and its kernel is managed by the hypervisor, not by apt inside the container. Scoping the wave to "noble hosts" is what keeps the verification honest instead of producing a 24/25 that reads like a bug.

The `deb_packages` check is the other half of the picture, run per host: on `fleetdm-server` the database shows the wave landed as installs (134, 136, 137, 138, 139, and 142 all present, latest `-142.142`). Package rows tell you *available*; `kernel_info` tells you *active*. A mitigation report quotes the second one.

## Part 3: the open list, and how it stays watched

The watchlist after this wave, exactly as it stands:

1. **CVE-2026-53362 and CVE-2026-53266** remain open on all noble hosts until the USN that fixes them lands in noble. The closure condition is written down: a kernel version that contains the fix commits, verified by the same `kernel_info` query, then a reboot wave, then the watchlist entry is retired. Nothing is closed on a package version number alone.
2. **automater's reboot** sits in the queue. The box is a GPU inference node, so the window lands around workloads, and the kernel there does not block the KEV ceiling anyway.
3. **ad-guard-home's kernel** is a hypervisor-side patch, tracked with the Proxmox host upgrades, not the fleet wave.

Each item has a name, an owner state (the agent's logbook holds it, the reboot needs your green light), and a written closure condition. That is the difference between a backlog and a watchlist.

## What the harness buys you

Strip the branding and the workflow is a pipeline with four checkpoints:

```
release query + checksum          stop, swap, migrate, start
        |                                    |
        v                                    v
   trust the bytes                verify the port, not the unit
        \                                /
         \                              /
          v                            v
      live kernel query ----> installed vs running split
          |
          v
     watchlist with closure conditions
```

- **The agent verifies before it acts**, because the memory layer remembers which gotchas have bitten before (the nginx cascade, the mandatory migration step, the is-active-that-lies) and encodes them as a runbook the agent follows rather than re-derives.
- **The MCP layer keeps it boring**: scope, SQL, per-host results. No session management, no polling loops, no jq archaeology.
- **Local inference keeps it private**: the entire session, including the hostnames and the KEV state, ran against an on-network vLLM endpoint.
- **The human stays at the green light.** Diagnosis, verification, and the draft plan are the agent's. The reboot and any destructive step need a "proceed", and only per-task.

The uncomfortable truth the verification step keeps surfacing: a patched package is not a mitigation. The reboot is the mitigation, the kernel in memory is the evidence, and the watchlist is the honest place for the vulnerabilities that do not have a fix yet. Everything else is theater.
