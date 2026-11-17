---
canonical: "https://karmine05.github.io/dirtyfrag-blog/posts/one-control-plane-three-operating-systems/"
meta-article:modified_time: "2026-11-16T16:00:00-05:00"
meta-article:published_time: "2026-11-16T16:00:00-05:00"
meta-article:section: posts
meta-author: Dhruv Majumdar
meta-description: "A mixed-OS fleet — Windows, macOS and DMZ Ubuntu — under one Fleet server. Labels decide scope, MDM profiles do the setting, a full policy layer verifies, and every control reports its status back per host."
meta-keywords: fleet,fleetdm,device-management,mdm,cis,compliance,windows,macos,linux,ubuntu,osquery,labels,configuration-profiles,dmz,active-directory,security-ops,endpoint-management
meta-og:description: "A fleet across Windows, macOS and DMZ Linux runs on one Fleet server. Labels decide scope, MDM profiles set, the policy layer verifies, and every control reports back per host."
meta-og:locale: en
meta-og:site_name: "karmine's notes"
meta-og:title: "One control plane, three operating systems"
meta-og:type: article
meta-og:url: "https://karmine05.github.io/dirtyfrag-blog/posts/one-control-plane-three-operating-systems/"
meta-title: "One control plane, three operating systems · karmine's notes"
meta-twitter:card: summary
meta-twitter:description: "Windows, macOS and DMZ Linux under one Fleet server: labels decide scope, profiles do the setting, every control reports back."
meta-twitter:title: "One control plane, three operating systems"
title: "One control plane, three operating systems"
slug: one-control-plane-three-operating-systems
date: "2026-11-16T16:00:00-05:00"
categories:
  - Security-Ops
tags:
  - Fleet
  - Device-Management
  - MDM
  - CIS
  - Compliance
  - Windows
  - macOS
  - Linux
  - Osquery
  - Security-Ops
showTableOfContents: true
---

{{< figure src="images/fig1-architecture.svg" alt="Fleet architecture: Windows workstations and domain controllers, macOS machines and a DMZ of Ubuntu servers, each running one osquery agent, with MDM channels for the client OSes, all feeding a single Fleet server" caption="The whole estate: Windows workstations and domain controllers, a handful of Macs, and a DMZ of Ubuntu servers. One osquery agent per host (osquery is the open-source agent Fleet ships; it answers SQL questions about the machine); the MDM channels ride the same server for the enrolled Windows and Apple hosts." >}}

> **One sentence:** A mixed fleet spanning three operating systems and multiple join states runs on one Fleet server, with dynamic labels deciding what applies where, MDM profiles doing the setting, a full policy layer verifying it, and a verified state per profile per host.

|                     |                                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **The fleet**       | Windows workstations and domain controllers, a handful of macOS machines, a DMZ of Ubuntu servers                                      |
| **The control plane** | One Fleet server: console, REST API, fleetctl, fleet-mcp, and the Windows and Apple MDM endpoints                                    |
| **The scope**       | one label set, mostly live-evaluated osquery SQL; a subset carries the CIS baseline                                                   |
| **The policy layer** | hundreds of policies live in the server: the full CIS/STIG baseline for each OS, plus a house layer of operational checks, mostly software-update state |
| **The setting layer** | a few hundred Windows CSP profiles (CSP is the Configuration Service Provider API that MDM profiles write through) and a dozen-plus macOS profiles live; hundreds of check/fix scripts in the repo |
| **The proof**       | 100% of profiles verified on every MDM-enrolled Windows workstation, as of its last check-in                                        |

## The fleet, as it actually is

Most device management write-ups start from a homogeneous estate: one OS, one join state, one MDM. This one does not, and that is the point of the exercise.

| Audience                     | Join state                       | MDM                          |
| ---------------------------- | -------------------------------- | ---------------------------- |
| Windows 10 / 11 workstations | domain-joined and workgroup      | enrolled via mdm_bridge      |
| Windows Server 2022          | domain controllers               | none, by design              |
| macOS                        | MDM-enrolled and agent-only      | Apple MDM                    |
| Ubuntu, DMZ segment          | no AD involvement                | no MDM channel (server fleet) |

The Linux side is a real production DMZ: a docker swarm, a Wazuh cluster, AdGuard Home, the load balancer, an automation box, and the Fleet server itself, which manages its own box like everyone else.

Four audiences, four different capabilities: Windows that can do MDM and Windows that cannot, a Mac that is enrolled and one that is not, and a Linux segment made entirely of DMZ servers. Fleet ships an MDM channel for Linux desktops, and it earns its own post. This one is about what the server segment gets instead: full visibility and control, on the same plane. The management model has to absorb that spread without a second console, and that is the spec this post addresses.

## Scope is a label, and a label is a query

{{< figure src="images/fig2-labels.svg" alt="Label scoping flow: host attributes read by osquery feed dynamic label SQL queries, the labels gate profiles and policies, and each host receives exactly the set its labels select" caption="A label is an osquery query evaluated on a cycle. A host's profile set is the intersection of its labels, recomputed from facts, not from an admin's list." >}}

In Fleet the question *which hosts does this apply to* has one answer shape: a query. A dynamic label is an osquery `SELECT` the server evaluates on a cycle, and a host that matches is a member. No list to maintain, no group to join, no inventory spreadsheet to keep in sync.

Two labels from the CIS baseline, verbatim from the server:

```sql
-- CIS scope - Windows 11 workstations
SELECT 1 FROM os_version
WHERE platform = 'windows' AND name NOT LIKE '%Server%'
  AND CAST(build AS INTEGER) >= 22000;

-- CIS scope - macOS MDM enrolled
SELECT 1 FROM mdm WHERE enrolled = 'true';
```

The Windows MDM profiles gate on the enrollment itself:

```sql
SELECT 1 FROM registry
WHERE key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\%'
  AND name = 'ProviderID' AND data = 'Fleet';
```

A host that is not enrolled cannot match that label, so it does not receive the profiles. Scope is a fact the host reports, not a permission you grant.

Manual labels cover the one-off contexts a query should not own. `Windows domain joined` came into existence with one API call, applied where needed, and it now gates the LAPS profile. That is the whole lifecycle.

What the model buys:

- a new host self-scopes on its first check-in, with zero per-host configuration;
- a build change, an enrollment, or a join-state change re-scopes it automatically;
- *which hosts should be running X* is a question with a live answer, not a meeting.

Many of the Windows profiles in the team are per-build variants, and they exist because the labels make a variant a data problem instead of a forking problem. More on that below.

## One policy, the right kind of fix

{{< figure src="images/fig3-ladder.svg" alt="Remediation ladder: a policy checks one setting with SQL; on fail the fix is a CSP profile where MDM can write the setting, otherwise a check-and-apply script; catalog.csv names the fix for every policy" caption="Every control is a SQL check first. The OS capability picks the remediation, and the repo encodes the choice once." >}}

The baseline repo encodes a ladder for every control:

1. **Policy.** One SQL check, one setting, pass or fail per host, always on. The baseline carries the full set per OS: the CIS Windows 11 Intune benchmark across all its levels, the CIS macOS benchmark, and the DISA STIG for Ubuntu.
2. **CSP profile.** Where MDM can write the setting, the fix is a configuration profile: Windows CSP XML files and macOS `.mobileconfig` files, one per control family, plus Apple declarations (Declarative Device Management: declarative desired-state payloads the device applies and owns) where a richer data shape fits. Not every control ships as a profile, because some run as scripts on the target builds; the deployed families reach the server as a few hundred live CIS profiles, including the per-build Win 10 variants, plus a small set of house profiles: an RDP allow rule and an OS update policy.
3. **Script.** Where no CSP key exists on that OS build, the fix is a script that ships in check mode by default and flips to apply with one line.

`catalog.csv` turns the ladder into data. One row per policy, with columns for `csp_uri`, `profile_file`, `script_file`, `scope_label` and `scope_reason`. When a policy fails, the fix is a field lookup, not an investigation.

The script contract is what makes it safe to run unattended. Take the STIG check that wants `systemd-timesyncd` gone:

```sh
DEFAULT_MODE=--check   # flip one line to --apply for a remediation run

check() ( ! pkg_ok systemd-timesyncd )

apply() {
  pkg_ok chrony || apt_in chrony
  DEBIAN_FRONTEND=noninteractive apt-get purge -y -q systemd-timesyncd
}
```

Check mode changes nothing and exits 0 when the host is compliant, 1 otherwise. Apply mode makes the change and re-checks before reporting success. The same contract spans every remediation script in the repo, across all three OSes, and it is what lets a remediation run attach to a failing policy and run unattended.

## Windows: per-build profiles, four audiences

{{< figure src="images/fig4-windows-variants.svg" alt="Windows per-OS scoping: one CIS control family fans out to a full Win11 profile, a stripped Win10 variant, a script path for Server, and a domain-join-gated LAPS profile, each branch selected by labels" caption="The CSP surface is versioned, so one control family ships as label-gated variants: full set for Win 11, a per-build variant for Win 10, the script path for Server, and a join-state gate for LAPS." >}}

Windows is where the MDM depth shows. The workstations enroll through Fleet's `mdm_bridge`, the Windows MDM channel that runs on the Fleet server itself; the domain controllers stay outside MDM by design, since Server cannot enroll. They still carry every osquery-based policy check and take script remediations, so the absence of MDM removes a channel, not visibility.

The Windows profiles live in a single Fleet team (Fleet's workspace object that groups hosts, profiles and policies), and they are not hand-tuned files. They are control families and their per-build variants, each gated by labels:

- **Win 11 workstations** (build 22000 or later) get the full profile: every CSP key the benchmark names.
- **Win 10 workstations** (build below 22000) get a `CIS-Win10-*` variant with the keys that build does not carry removed. The Windows CSP surface versions its keys, and a control that writes a dozen keys on a current build writes a handful on an older one. The variants in the team are exactly that delta, scoped by the build label so the wrong OS never sees the wrong file.
- **LAPS** is the scope that is not about the OS. Windows LAPS rotates the local administrator password and backs the result up to a directory, AD or Entra; the CSP writes the rule, and LAPS enforces it. The LAPS profile therefore carries a domain-joined label on top of its OS scope, and the workgroup hosts in the fleet simply do not receive the control. The population that can pass it is exactly the population that gets it. For the boxes LAPS does not reach, local admin is not a standing state either: it is a grant made from Fleet on demand.

The result this week: every enrolled workstation came back fully verified, the workgroup one a profile short because LAPS does not apply there. Its state shows in the same view as the domain-joined hosts.

## macOS: MDM the Apple way

The MacBook Pro is MDM-enrolled in Fleet. The root CA profile and the fleetd configuration (Fleet's agent daemon) arrive through Apple MDM, and declarative management is available for the settings that outgrow classic profiles. The Mac mini runs agent-only and still gets the full policy layer.

The scope label is one line: `SELECT 1 FROM mdm WHERE enrolled = 'true'`. The full CIS macOS policy set runs against both machines; the baseline profiles and scripts are the fix path, and the live profiles on the server add disk encryption, Santa, and the enrollment set; the MDM-enrolled label is the only thing separating what the MDM channel delivers from what the agent channel delivers. Enrollment changes, and the set changes with it.

## The DMZ Linux: full visibility, no MDM channel

Every box in the DMZ is a server. Fleet ships an MDM channel for Linux desktops: first-class support across the major distros, with remote lock and wipe, LUKS2 disk-encryption enforcement, script execution, and a self-service page. That is a follow-up post, because the machines in this DMZ are not desktops. For them the MDM channel stays off, and the management surface is the same three-piece kit minus the profile channel:

- **Policies.** The same SQL checks, the same pass/fail model: the full Ubuntu STIG baseline, running against the swarm nodes, the indexers, and the network gear.
- **Scripts.** The same check/apply contract: patching, service hardening, CVE remediations, each one attachable to the policy it fixes.
- **Live queries and scheduled packs.** For the state a one-shot check cannot own.

No MDM channel does not mean no control. Every box reports the same osquery surface the rest of the estate sees: software, processes, services, disk and network state, and the STIG pass/fail on each one. A box that drifts shows up in the same list as a drifted Mac or Windows host, and the fix is a script that runs at scale, on demand or attached to the failing policy.

The point is that the DMZ boxes do not get a second management model. They join the same label space, the same policy view, and the same status page. *Which STIG controls are failing anywhere in the estate* is one list, not three, and it updates itself.

The Fleet server deserves the same scrutiny, because it is the one box that can reach every other box. It gets no special treatment: it is one of the DMZ Ubuntu servers, it runs the same STIG baseline, and its own state is GitOps-backed, so every change to it lands in version control and is auditable and restorable like any other host in the estate. Its MDM endpoints are reachable only from within the estate. When it is down, check-ins queue on the agents and the estate resumes when it is back; no host state is lost in the interval.

## Monitoring: every profile carries a receipt

{{< figure src="images/fig5-monitoring-loop.svg" alt="Monitoring loop: labels re-evaluate, each host's profile set is computed, pushed and applied, the device reports per-key status at check-in, and the console shows verified pending or failed per profile per host" caption="The MDM check-in is not fire-and-forget: the device reports per-key status, so each profile has a verified state per host, as of its last check-in." >}}

MDM deployments usually end at *delivered*. Fleet's check-in does not. When a Windows host syncs, it reports the status of every key it applied, and the server stores that per profile, per host. The console shows verified, pending or failed, with the offending key in the detail column when something is off. A fully green row is not *the profile was sent*; it is *the profile's keys are on the device and the device says so*. Check-ins land on the order of a minute, so the view is live. A host that stops checking in shows as offline in the same view, and its verified state reads as last-known, not current: the 100% is only as fresh as the newest check-in.

That changes the shape of the compliance conversation. Coverage is a count. Drift is a diff. *Which hosts are missing control X* is a query, and the answer updates itself the moment a host changes state, because the label evaluation and the check-in loop keep running.

## Why this scales

Walk a new host through the system and notice what does not happen:

1. Install the agent, enroll the Mac, or register the Windows host for MDM.
2. First check-in. The labels evaluate against its OS, build, enrollment and join state.
3. Its profile set computes itself. Nothing is assigned per host.
4. The first sync applies it; the next check-in returns the status.

From then on, change flows in from facts rather than from an administrator. A host re-images to a newer build and its profile set recomputes. A Mac gets enrolled and it starts matching the MDM label. A new Win 11 machine appears and its full profile set lands on its first sync. The repo is the only thing a human maintains, and it is versioned, reviewable, and deployable with `fleetctl`.

That is the whole operating model: **labels are the scope, profiles are the fix, policies are the proof**, and the server is the one place all three meet.

## Run it yourself

The backbone is the [fleet-cis-baselines](https://github.com/karmine05/fleet-cis-baselines) repo: hundreds of policies, MDM profiles for both client OSes, check/fix scripts, and a scope-label set, plus `apply_policy_scope.py`, which wires policies to labels with a dry run before anything touches a team.

```sh
fleetctl apply -f labels/labels.yml
fleetctl apply --policies-team "Workstations" -f windows/policies/cis-win11-l1.yaml
labels/apply_policy_scope.py --team-id 1   # dry run until you pass --apply
```

Every policy row in `catalog.csv` names the fix for its failure: the profile file, the script file, the scope label, and the reason. Use any file on its own; you do not need the whole repo.

Related: **[the fleet-mcp manifesto](https://karmine05.github.io/dirtyfrag-blog/posts/fleet-mcp-manifesto/)** for the agent-facing side of this same server, and **[pre-CVE response with Fleet](https://karmine05.github.io/dirtyfrag-blog/posts/pre-cve-response-with-fleet/)** for the policy-driven remediation path on the Linux side.

## The through-line

The old model stacks a tool per audience: one MDM for Windows, one for the Macs, one config manager for the Linux, and a spreadsheet for the rest. This fleet runs on one server because the primitive underneath all three audiences is the same: a query against the host, a scope derived from it, a change applied when it is due, and a status reported when it lands. The operating system changes. The model does not.
