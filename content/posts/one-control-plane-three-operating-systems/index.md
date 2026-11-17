---
title: One control plane, three operating systems
date: '2026-11-16T16:00:00-05:00'
slug: one-control-plane-three-operating-systems
description: How one Fleet server manages Windows, macOS and Ubuntu servers in a mixed estate. Labels set the scope, MDM profiles apply the settings, policies prove they took, and every host reports its own status.
tags:
- fleet
- device-management
- mdm
- cis
- compliance
- windows
- macos
- linux
- osquery
- security-ops
categories:
- security-ops
---

{{< figure src="images/fig1-architecture.svg" alt="Fleet architecture: Windows workstations and domain controllers, macOS machines and a DMZ of Ubuntu servers, each running one osquery agent, with MDM channels for the client OSes, all feeding a single Fleet server" caption="The whole estate: Windows workstations and domain controllers, a handful of Macs, and a DMZ of Ubuntu servers. Every host runs one osquery agent (the open-source agent Fleet ships, which answers SQL questions about the machine). Enrolled Windows and Apple hosts also take MDM profiles from the same server." >}}

> **The short version:** one Fleet server runs a mixed fleet of Windows, macOS and Ubuntu hosts. Labels decide which settings apply to which host. MDM profiles apply the settings. Policies check that each one took. Every host reports its own status back to the same console.

## Who gets what from this post

**If you run IT (CIO, head of IT).** One platform replaces a separate tool for each operating system. You get a compliance number that comes from the devices themselves, and every configuration change lives in Git, so an auditor can see who changed what and when. Start with [the proof](#every-profile-carries-a-receipt) and [why this scales](#why-this-scales).

**If you manage a device team.** A new laptop needs no ticket and no per-host assignment: it enrolls, matches its labels and receives its settings on the first check-in. What your team maintains is one repository. Start with [the fleet as it is](#the-fleet-as-it-actually-is) and [scope is a label](#scope-is-a-label-and-a-label-is-a-query).

**If you are the admin doing the work.** The SQL, the profile structure, the check/apply script contract and the commands are all below. Start with [one policy, the right kind of fix](#one-policy-the-right-kind-of-fix) and [run it yourself](#run-it-yourself).

|                       |                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **The fleet**         | Windows workstations and domain controllers, a handful of macOS machines, a DMZ of Ubuntu servers                                     |
| **The control plane** | One Fleet server: console, REST API, fleetctl, fleet-mcp, and the Windows and Apple MDM endpoints                                     |
| **The scope**         | One label set, mostly live osquery SQL; a subset carries the CIS baseline                                                             |
| **The policy layer**  | Hundreds of policies: the full CIS or STIG baseline for each OS, plus a house layer of operational checks, mostly software-update state |
| **The setting layer** | A few hundred Windows CSP profiles (CSP is the Configuration Service Provider API that MDM profiles write through), a dozen-plus macOS profiles, and hundreds of check/fix scripts in the repo |
| **The proof**         | Every profile in scope for an MDM-enrolled Windows workstation shows as verified, as of that host's last check-in                    |

## The fleet, as it actually is

Most device management write-ups assume one OS, one join state and one MDM. This estate has none of those, and that is why it makes a useful test.

| Audience                     | Join state                       | MDM                           |
| ---------------------------- | -------------------------------- | ----------------------------- |
| Windows 10 / 11 workstations | domain-joined and workgroup      | enrolled in Fleet MDM         |
| Windows Server 2022          | domain controllers               | none, by design               |
| macOS                        | MDM-enrolled and agent-only      | Apple MDM                     |
| Ubuntu, DMZ segment          | no AD involvement                | no MDM channel (server fleet) |

The Linux side is a real production DMZ of application, monitoring and network-service servers. The Fleet server sits in it and is managed like every other box.

That gives four audiences with different capabilities: Windows that can take MDM and Windows that cannot, a Mac that is enrolled and one that is not, and a Linux segment made up entirely of servers. The management model has to cover all of them without a second console.

## Scope is a label, and a label is a query

{{< figure src="images/fig2-labels.svg" alt="Label scoping flow: host attributes read by osquery feed dynamic label SQL queries, the labels gate profiles and policies, and each host receives exactly the set its labels select" caption="A label is an osquery query that the server re-evaluates on a cycle. A host's profile set is the intersection of its labels, recomputed from what the host reports." >}}

In Fleet, the question "which hosts does this apply to?" always has the same answer shape: a query. A dynamic label is an osquery `SELECT` that the server re-runs on a cycle, and any host that matches is a member. There is no list to maintain and no spreadsheet to keep in sync.

Two labels from the CIS baseline, as they exist on the server:

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

A host that is not enrolled cannot match that label, so it never receives the profiles. Scope comes from what the host reports about itself, which means nobody has to remember to grant it.

Manual labels cover the one-off cases a query should not own. `Windows domain joined` was created with one API call, applied to the right hosts, and now gates the LAPS profile.

What this buys you:

- A new host scopes itself on its first check-in, with no per-host configuration.
- A build change, an enrollment or a join-state change re-scopes the host automatically.
- "Which hosts should be running X?" has a live answer instead of a meeting.

Many of the Windows profiles are per-build variants. Labels turn a variant into a data problem, and that keeps the repo from forking. More on that below.

## One policy, the right kind of fix

{{< figure src="images/fig3-ladder.svg" alt="Remediation ladder: a policy checks one setting with SQL; on fail the fix is a CSP profile where MDM can write the setting, otherwise a check-and-apply script; catalog.csv names the fix for every policy" caption="Every control starts as a SQL check. What the OS can do decides the remediation, and the repo records that choice once." >}}

The baseline repo uses the same ladder for every control:

1. **Policy.** One SQL check on one setting, pass or fail per host, always on. The baseline covers the full set per OS: the CIS Windows 11 Intune benchmark across its levels, the CIS macOS benchmark, and the DISA STIG for Ubuntu.
2. **CSP profile.** Where MDM can write the setting, the fix is a configuration profile: Windows CSP XML or a macOS `.mobileconfig`, one per control family. Apple declarations (Declarative Device Management, where the device applies and owns a desired state) cover settings that need a richer shape. Some controls run as scripts on certain builds instead, so not every control ships as a profile. The live set is a few hundred CIS profiles, including per-build Windows 10 variants, plus a few house profiles such as an RDP allow rule and an OS update policy.
3. **Script.** Where no CSP key exists for that OS build, the fix is a script. It ships in check mode and flips to apply with one line.

`catalog.csv` turns the ladder into data: one row per policy, with columns for `csp_uri`, `profile_file`, `script_file`, `scope_label` and `scope_reason`. When a policy fails, finding the fix means reading one row.

The script contract is what makes unattended runs safe. Take the STIG check that wants `systemd-timesyncd` gone:

```sh
DEFAULT_MODE=--check   # flip one line to --apply for a remediation run

check() ( ! pkg_ok systemd-timesyncd )

apply() {
  pkg_ok chrony || apt_in chrony
  DEBIAN_FRONTEND=noninteractive apt-get purge -y -q systemd-timesyncd
}
```

Check mode changes nothing and exits 0 when the host is compliant, 1 when it is not. Apply mode makes the change, then re-checks before it reports success. Every remediation script in the repo follows this contract on all three OSes, so a script can be attached to a failing policy and run without anyone watching.

## Windows: per-build profiles, four audiences

{{< figure src="images/fig4-windows-variants.svg" alt="Windows per-OS scoping: one CIS control family fans out to a full Win11 profile, a stripped Win10 variant, a script path for Server, and a domain-join-gated LAPS profile, each branch selected by labels" caption="The CSP surface is versioned, so one control family ships as label-gated variants: the full set for Win 11, a per-build variant for Win 10, the script path for Server, and a join-state gate for LAPS." >}}

Windows is where the MDM depth shows. Workstations enroll in Fleet's built-in Windows MDM. The domain controllers stay out of MDM by design, because Windows Server does not enroll. They still carry every osquery-based policy check and take script remediations, so the missing MDM channel costs a delivery route and leaves visibility intact.

The Windows profiles live in a single fleet (Fleet's workspace object for hosts, profiles and policies; it was called a "team" before Fleet 4.83). They are control families with per-build variants, each gated by labels:

- **Win 11 workstations** (build 22000 or later) get the full profile, with every CSP key the benchmark names.
- **Win 10 workstations** (build below 22000) get a `CIS-Win10-*` variant with the keys that build does not carry removed. The Windows CSP surface versions its keys: a control that writes a dozen keys on a current build writes a handful on an older one. The variants in the fleet are exactly that difference, scoped by the build label, so no machine sees the wrong file.
- **LAPS** is scoped by something other than the OS. Windows LAPS rotates the local administrator password and backs it up to a directory (AD or Entra). The CSP writes the rule and LAPS enforces it. The LAPS profile therefore carries a domain-joined label on top of its OS scope, and the workgroup hosts do not receive it. Only the hosts that can pass the control are asked to. For machines LAPS does not reach, local admin is a grant made from Fleet on demand, and nobody holds it as a standing right.

At the last check-in, every enrolled workstation reported all of its in-scope profiles as verified. The workgroup machine has one fewer profile in scope because LAPS does not apply to it, and its status sits in the same view as the domain-joined hosts.

## macOS: MDM the Apple way

The MacBook Pro is MDM-enrolled in Fleet. The root CA profile and the fleetd configuration (fleetd is Fleet's agent) arrive through Apple MDM, and declarative management is available for settings that outgrow classic profiles. The Mac mini runs agent-only and still gets the full policy layer.

The scope label is one line: `SELECT 1 FROM mdm WHERE enrolled = 'true'`. The full CIS macOS policy set runs against both machines. The baseline profiles and scripts are the fix path, and the live profiles on the server add disk encryption, Santa and the enrollment set. The MDM-enrolled label is the only thing that separates what the MDM channel delivers from what the agent channel delivers, so when a Mac's enrollment changes, its set changes with it.

## The DMZ Linux: full visibility, no MDM channel

Every box in the DMZ is a server. Fleet also manages Linux desktops, with lock and wipe, disk-encryption key escrow and a self-service page, but those features target laptops, and this segment has none. That deserves its own post. For servers, the management surface is the same kit minus the profile channel:

- **Policies.** The same SQL checks and the same pass/fail model: the full Ubuntu STIG baseline running across the container hosts, the log indexers and the network appliances.
- **Scripts.** The same check/apply contract, used for patching, service hardening and CVE remediations, each one attachable to the policy it fixes.
- **Live queries and scheduled packs.** For state that a one-shot check cannot cover.

No MDM channel still leaves plenty of control. Every box reports the same osquery surface as the rest of the estate (software, processes, services, disk and network state), plus its STIG pass/fail. A server that drifts appears in the same list as a drifted Mac or Windows host, and the fix is a script that runs at scale, on demand or attached to the failing policy.

DMZ boxes join the same label space, the same policy view and the same status page, so nothing gives them a second management model. "Which STIG controls are failing anywhere in the estate?" gets one list instead of three, and the list updates itself.

The Fleet server gets the same scrutiny because it is the most trusted system in the estate. It is one of the DMZ Ubuntu servers, runs the same STIG baseline, and its own configuration is GitOps-backed, so every change lands in version control and can be audited and restored like any other host. If the server goes down, the agents keep running their local checks and report again when it returns.

## Every profile carries a receipt

{{< figure src="images/fig5-monitoring-loop.svg" alt="Monitoring loop: labels re-evaluate, each host's profile set is computed, pushed and applied, the device reports per-key status at check-in, and the console shows verified pending or failed per profile per host" caption="The MDM check-in reports back. The device returns per-key status, so each profile has a verified state per host, as of its last check-in." >}}

Most MDM deployments stop at "delivered." Fleet's check-in goes further. When a Windows host syncs, it reports the status of every key it applied, and the server stores that per profile, per host. The console shows verified, pending or failed, with the offending key in the detail column when something is wrong. A green row therefore means the profile's keys are on the device and the device confirmed it, which is stronger than "the profile was sent."

Windows hosts check in often (Fleet sets the first retry interval at one minute), so the view stays close to live. A host that stops checking in shows as offline in the same view, and its verified state reads as last known. The coverage figure is only as fresh as the newest check-in, and the console says so.

This changes the compliance conversation. Coverage becomes a count you can read off a screen, and drift becomes a diff. "Which hosts are missing control X?" is a query, and its answer updates when a host changes state, because label evaluation and the check-in loop keep running.

## Why this scales

Walk a new host through the system and notice the steps that never happen:

1. Install the agent, enroll the Mac, or register the Windows host for MDM.
2. On the first check-in, the labels evaluate against its OS, build, enrollment and join state.
3. Its profile set computes itself. Nobody assigns anything per host.
4. The first sync applies the set, and the next check-in returns the status.

From then on, changes flow from what the hosts report. A host re-images to a newer build and its profile set recomputes. A Mac gets enrolled and starts matching the MDM label. A new Win 11 machine appears and its full set lands on its first sync. The only thing a person maintains is the repo, which is versioned, reviewable and deployable with `fleetctl`.

The operating model fits in one line: **labels are the scope, profiles are the fix, policies are the proof**, and the Fleet server is where all three meet.

## Run it yourself

The backbone is the [fleet-cis-baselines](https://github.com/karmine05/fleet-cis-baselines) repo. It holds policies for Windows, macOS and Ubuntu, MDM profiles for both client OSes, check/fix scripts, and a scope-label set. It also includes `apply_policy_scope.py`, which wires policies to labels and does a dry run before it touches a fleet.

```sh
fleetctl apply -f labels/labels.yml
fleetctl apply --policies-fleet "Workstations" -f windows/policies/cis-win11-l1.yaml
labels/apply_policy_scope.py --team-id 1   # dry run until you pass --apply
```

Each policy row in `catalog.csv` names the fix for its own failure: the profile file, the script file, the scope label and the reason. Any file works on its own, so you can take one control without adopting the whole repo.

Related reading: **[the fleet-mcp manifesto](https://karmine05.github.io/dirtyfrag-blog/posts/fleet-mcp-manifesto/)** covers the agent-facing side of this same server, and **[pre-CVE response with Fleet](https://karmine05.github.io/dirtyfrag-blog/posts/pre-cve-response-with-fleet/)** shows the policy-driven remediation path on Linux.

## What to take away

The usual model stacks one tool per audience: an MDM for Windows, another for the Macs, a config manager for Linux, and a spreadsheet for whatever is left. This estate runs on one server because all three audiences share the same primitive: a query against the host, a scope derived from the answer, a change applied when it is due, and a status reported when it lands. The operating systems differ, and the model stays the same.
