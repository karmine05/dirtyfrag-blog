---
title: About karmine
date: '2025-12-21T09:00:00-05:00'
lastmod: '2026-11-16T09:00:00-05:00'
description: About Dhruv Majumdar — VP of Security Solutions, head of security for a mixed-OS fleet. Two decades leading MxDR, compromise assessments, and cyber threat intelligence; now driving security with agents and device policy.
summary: About Dhruv Majumdar — security operations across two decades, now building the auditable AI layer of the stack.
draft: false
type: blog
menus:
  main:
    identifier: about
    weight: 20
reading_time: false
featured_image: none
---

{{< figure src="images/infographic.svg" alt="Infographic: two decades leading MxDR, compromise assessments, and cyber threat intelligence — now driving security with agents and device policy on one control plane" >}}

**Dhruv Majumdar** — **VP of Security Solutions**, head of security for a mixed-OS fleet. Two decades working in and leading **MxDR** programs, **compromise assessments**, and **Cyber Threat Intelligence** — the programs where the defense has to be reproducible, not just plausible. Now the job is being driven forward by **agents and device policy**: the operators are human and agent, and the control plane decides what either one may touch.

These notes are the working-out: the tools, the patterns, and the moves that survive contact with real adversaries and real fleets.

Most of what I write touches the seam between detection theory and operational reality — where MxDR programs run on artifacts not catalogs, where vulnerability response works backwards from exploit primitives instead of forwards from a CVE ID, and where a red team's "found it" only matters if the blue side can reproduce it on every endpoint they own.

The seam has moved again. The operators are no longer only human — agents now sit inside the security stack, and the question is no longer *can they help* but *can their work still be audited*. These notes follow agents through that stack: how an agent earns the right to touch a fleet, how its work stays inspectable, and how you keep sight of the AI layer running on your own endpoints. The rule across all of it: **the model accelerates the work without hiding it.**

## The AI-forward bet

Three things I have built and shipped, each an answer to the same question — *can an agent do this on my fleet, and can I still audit it?*

- **Ask, and see the SQL.** [fleet-mcp](https://karmine05.github.io/dirtyfrag-blog/posts/fleet-mcp-manifesto/) turns Fleet into a typed tool catalog any AI agent can call. English in, a real osquery scan across every host you own out — with the SQL and the assumptions shown to the analyst, not buried in a trace.
- **Hunt with the agent in the loop.** [Vibe hunting](https://karmine05.github.io/dirtyfrag-blog/posts/vibe-hunting-clickfix-fleet-mcp-atc/): state the intent in English, the agent composes the SQL, fuses browser, filesystem and kernel evidence into one OCSF timeline, reaches a verdict, and acts on it. The analyst reviews the timeline, not the tool output.
- **See the AI layer you are running.** [agentic-detector](https://karmine05.github.io/dirtyfrag-blog/posts/agentic-detector/): one osquery table over MCP servers, agent CLIs, IDE plugins, live AI sockets, and the instruction files that tell agents what they are allowed to do. An npx-fetched MCP server with shell-exec capability is now part of your attack surface — so it belongs in your inventory.

The writing runs on a living lab: a mixed-OS estate where agents operate through the same control plane as the humans, and every claim in these notes comes back as a query result rather than a screenshot. Start with [one control plane, three operating systems](https://karmine05.github.io/dirtyfrag-blog/posts/one-control-plane-three-operating-systems/).

## What I work on

- **MxDR / VMDR and detection engineering** — the full lifecycle from signal to disposition, across Mac, Windows, and Linux
- **Threat hunting as a craft** — artifact-driven, adversarially informed, and reproducible across fleets
- **Cyber Threat Intelligence** — CTI that changes what you look for, not just what you read
- **Red team operations** — the offense side, focused on what actually gets past real defenses
- **AI for Security Operations** — natural-language interfaces over Fleet, osquery, and MCP that make agent output auditable, with SQL still shown to the human analyst

## Speaking

I present at security conferences and user groups. Recent stages: **BSides**, **DC416**, **conINT**, **HacKP**.

## On the air

I've appeared on several security podcasts over the past year and a half:

- [**Beyond the Alert**](https://open.spotify.com/show/5d3b3513-881a-425a-88c9-d6440a31b5d5) — AI agents breaking out of the lab, AI in vulnerability triage, hunting with the model, agentic CTI, agentic SOC, AI supply chain
- [**Detection at Scale**](https://podcasters.spotify.com/pod/show/detection-at-scale) — MDM, device management, and why the endpoint is the new perimeter
- [**Blue Team Warrior**](https://podcasters.spotify.com/pod/show/blue-team-warrior) — MxDR in practice, detection engineering, and the operational reality of running a defense
- [**Hacking Security Radio**](https://hackingsecurityradio.com) — a 4-hour deep dive on hunting, CTI, and the MxDR lifecycle

## Find me

- [LinkedIn](https://www.linkedin.com/in/neondhruv/)
- [GitHub](https://github.com/karmine05)

---

*Opinions are my own.*
