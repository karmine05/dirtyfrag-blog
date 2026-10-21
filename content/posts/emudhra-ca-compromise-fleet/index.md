---
title: "eMudhra CA Key Compromise: Find and Fix the Trust Stores Your Browser Doesn't Cover"
date: 2026-10-21T12:00:00-04:00
draft: false
tags: ["fleet", "osquery", "pki", "tls", "certificates", "macos", "windows", "linux", "detection-engineering", "remediation", "emudhra"]
categories: ["security-ops"]
description: "Plain-language brief on the October 2026 eMudhra intermediate CA key compromise, its blast radius across curl, Go, Node.js, Python and Fleet's own agent, plus three validated Fleet queries and three remediation scripts for macOS, Windows and Linux."
summary: "Eight eMudhra intermediate CA keys were generated as tiny, guessable numbers, so anyone can forge a trusted certificate for any website. Browsers and operating systems blocked them within three days. Everything that keeps its own copy of the trusted roots did not: Linux CA bundles, macOS /etc/ssl/cert.pem, Node.js, Python certifi, and the CA bundle Fleet's own agent uses to reach the Fleet server. This brief explains the blast radius in plain words and ships three Fleet queries and three Fleet scripts (macOS, Windows, Linux) that find and fix the exposure, tested on real hosts and containers."
showHero: false
showTableOfContents: true
showReadingTime: true
showWordCount: true
---

{{< alert "circle-info" >}}
**TL;DR.** Eight eMudhra intermediate CA keys can be recomputed by anyone. Browsers and OS trust stores are already protected. Tools that carry their **own** list of trusted roots are not, and that includes the bundle Fleet's agent uses. Run the three [queries](/dirtyfrag-blog/posts/emudhra-ca-compromise-fleet/#detect-three-fleet-queries) to find exposed hosts. Run the three [scripts](/dirtyfrag-blog/posts/emudhra-ca-compromise-fleet/#fix-three-fleet-scripts) to fix them.
{{< /alert >}}

## What happened, in plain words

Every HTTPS connection relies on a chain of trust. Your device holds a short list of **root** certificates. A root vouches for an **intermediate**. The intermediate signs the certificate a website shows you. If the chain checks out, your device believes it is talking to the real site.

A private key is supposed to be a random 384-bit number. In an April 2025 key ceremony, eMudhra produced eight intermediate CA keys that were [integers smaller than 256](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449). Anyone can try every value in milliseconds. Whoever holds one of those keys can sign a certificate for **any** hostname, and devices that trust the parent roots accept it.

Six of the intermediates issue TLS certificates; two sign code. The TLS ones reach `emSign ECC Root CA - G3`, the root most devices trust, and every one of the eight also has a twin cross-signed by Sectigo's `AAA Certificate Services` root. A researcher reported the keys on 17 October. eMudhra revoked all eight on 18 October.

{{< figure src="images/hero.svg" alt="Three panels: eight eMudhra intermediate keys generated as numbers below 256; an attacker recomputes a key and forges certificates for any hostname or signs Windows malware; browsers and operating systems block the forged chain while Linux CA bundles, macOS /etc/ssl/cert.pem, Node.js, Python certifi and the fleetd osquery bundle still trust it" caption="The keys were never stolen. They were guessable from day one, and every client with a stale CA copy still believes them." >}}

## Why it still needs action

The big vendors moved fast. Chrome and Firefox pushed blocks on 17 October, Apple on 19 October, and Microsoft on 20 October ([emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/)). Google [found](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/) no TLS certificate under these intermediates in Certificate Transparency logs before the block.

Those fixes only reach software that asks the OS or checks revocation. A lot of software does neither. It ships a frozen file of trusted roots and believes it until someone updates the file. That is where the risk lives now.

## Blast radius

An attacker still needs a spot on the network path to use a forged certificate: rogue Wi-Fi, a compromised router or proxy, or DNS hijacking. With that, here is what each trust path gives them.

{{< figure src="images/blast-radius.svg" alt="Ladder of six trust paths from safest to most exposed: browsers blocked, OS trust stores blocked except offline hosts, Go programs depend on platform, system CA files exposed, runtimes with their own CA copy exposed, and the Fleet agent bundle exposed" caption="Browsers and OS stores are fine. The bottom three rows are where unpatched hosts leak." >}}

| Trust path | Fixed by the vendor push? | Worst case if left unpatched |
|---|---|---|
| **curl, wget, git, scripts** (Linux CA bundle, macOS `/etc/ssl/cert.pem`) | No. Apple did not update `/etc/ssl/cert.pem`. | Passwords and API tokens read in transit; `curl \| sh` installers swapped for malware. Package installs through apt or dnf stay safe because packages are GPG-signed. |
| **System-wide on Linux** (unpatched `ca-certificates`) | Only after a package update. On 21 October, Rocky Linux 9 and Fedora 44's stable repos still shipped the root. | Every OpenSSL or GnuTLS program on the server can be impersonated at once: backups, webhooks, monitoring agents, database clients. |
| **Go programs** | macOS and Windows: yes, Go asks the OS ([docs](https://pkg.go.dev/crypto/x509)). Linux: no, Go reads the system bundle. | Cloud CLIs, `kubectl`, `terraform` and agents hand their credentials to an impostor API. [Go 1.27.3 and 1.26.10](https://go.dev/doc/devel/release) reject these keys outright ([The Hacker News](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html)), but only after a rebuild. |
| **Node.js and Electron** | No. Official builds ship a [bundled Mozilla snapshot](https://nodejs.org/api/cli.html#--use-bundled-ca---use-openssl-ca) fixed at release, on every OS. | Service-to-service calls and API keys go to the attacker, even on a fully patched Windows or Mac. Fixed in Node.js 22.23.4, 24.22.1 and 26.12.1, and Electron 42.11.16, 43.8.1 and 44.9.1. |
| **Python `requests`** (pip-installed `certifi`) | No. certifi is its own CA copy. | Same as Node.js. Fixed in certifi 2026.10.19. Distro-packaged certifi points at the system bundle and follows it. |
| **Windows code signing** (two CS intermediates) | Yes, by Microsoft's disallowed list, if the host received it. | Malware signed "by eMudhra" passes checks that only ask whether a binary is signed by a trusted CA. |

### Fleet's own agent

Fleet's agent ships its own CA bundle at `/opt/orbit/certs.pem` (`C:\Program Files\Orbit\certs.pem` on Windows). osqueryd uses that file, not the OS store, for every TLS connection to the Fleet server. The file is written at install time and never refreshed. Fleet merged a fix that drops the emSign root on 21 October ([fleetdm/fleet#56173](https://github.com/fleetdm/fleet/pull/56173)). Only packages built with the next fleetctl release will include it, and hosts that are already enrolled keep the old file either way.

The orbit updater itself is written in Go. On macOS and Windows it verifies TLS through the OS, so the vendor block covers it. On Linux it reads the system bundle. As of 21 October no orbit release is built with fixed Go yet.

**Worst case:** an impostor Fleet server collects every host's query results and agent keys, and can send its own queries. On a Linux host whose system bundle is also stale, orbit would accept that server too. If scripts are enabled, orbit runs the scripts it is handed as root.

## Detect: three Fleet queries

Each query returns `finding | item | detail | status`, one row per signal. No row for a finding means it was not found.

- [emudhra-macos.sql](/dirtyfrag-blog/code/emudhra-macos.sql)
- [emudhra-windows.sql](/dirtyfrag-blog/code/emudhra-windows.sql)
- [emudhra-linux.sql](/dirtyfrag-blog/code/emudhra-linux.sql)

Run them as a live report from the Fleet UI, or with `fleetctl`:

```bash
fleetctl report --labels "macOS" --query "$(cat emudhra-macos.sql)"
```

| Finding | What it means |
|---|---|
| `compromised_intermediate_present` | One of the 16 revoked certificates sits in a local store. Investigate who put it there. |
| `root_in_ca_bundle` / `root_in_pem_bundle` | A system CA file still trusts a compromised root. Command-line tools are exposed. |
| `fleetd_osquery_ca_bundle` | The agent's own bundle still trusts a compromised root. osquery-to-Fleet traffic is exposed. |
| `apple_block_applied` / `disallowed_ctl_sync` | The Apple or Microsoft block landed. `STALE` or `NOT_SYNCED` means it did not. |
| `disallowed_store_block` | Windows only: how many of the 16 certificates the remediation script has explicitly distrusted. |
| `ctl_autoupdate_policy` | Group Policy blocks Microsoft's automatic distrust updates. |
| `ca_certificates_pkg`, `homebrew_ca_certificates`, `python_certifi`, `toolchain` | Package and runtime versions to compare against the fixed versions above. |
| `go_binary` | A Go tool in a user's `go/bin` built with Go older than 1.27.3 or 1.26.10. |
| `root_in_keychain` / `root_in_cert_store`, `fleetd_agent`, `host` | Informational. Apple and Microsoft ship both roots on every device and block the intermediates instead, so these rows stay after the fix. |

## What our lab fleet showed

We ran the queries across a 31-host lab: Windows desktops and servers, a Mac, and a Linux cluster.

{{< figure src="images/fleet-results.svg" alt="Scoreboard: Windows 6 hosts with 0 exposed through the OS, macOS 1 host with an exposed CLI trust bundle, Linux 24 hosts with 9 unpatched CA bundles; below, anonymized report rows for each platform" caption="Hostnames anonymized and long status text shortened. Rows come from the Fleet report exports, except the fleetd row, which comes from the updated macOS query." >}}

Three lessons came out of it:

1. **Microsoft's automatic update worked everywhere.** All six Windows hosts synced the disallowed list within a day. The one real gap was a Node.js runtime.
2. **Patched and unpatched Linux hosts sat side by side.** Nine of 24 Ubuntu hosts had never pulled the October security update. A working update pipeline on the other 15 did not mean the whole fleet was covered.
3. **Read version rows with context.** The first Linux export flagged Ubuntu's own `certifi` on 23 hosts. That package points at the system bundle, so it was a false alarm. The published query marks it `OK_DISTRO_CERTIFI`.

## Fix: three Fleet scripts

Each script is idempotent, keeps a `*.pre-emudhra` backup of every file it edits, and exits `0` when protected, `2` when something needs a look, and `1` on error.

| Script | What it does |
|---|---|
| [emudhra-remediate-macos.sh](/dirtyfrag-blog/code/emudhra-remediate-macos.sh) | Removes the two roots from `/etc/ssl/cert.pem` and the fleetd bundle. Upgrades Homebrew `ca-certificates` and `certifi` as the Homebrew owner. |
| [emudhra-remediate-linux.sh](/dirtyfrag-blog/code/emudhra-remediate-linux.sh) | Upgrades `ca-certificates` (apt, dnf, yum, zypper, apk). Where the distro has no fix yet, distrusts the roots the native way, then cleans the fleetd bundle. |
| [emudhra-remediate-windows.ps1](/dirtyfrag-blog/code/emudhra-remediate-windows.ps1) | Adds all 16 compromised intermediates to the machine's Untrusted Certificates store, then cleans the fleetd bundle. |

Before editing the fleetd bundle, every script fetches the Fleet server's certificate chain and checks that it still ends at a root left in the filtered file. Hosts pinned to their own Fleet certificate skip that check, because osquery does not use the bundle there. If a script can't prove it is safe, it changes nothing and says so. osquery reloads the file on its next connection, so no agent restart is needed.

To roll out:

1. Upload the scripts under **Controls → Scripts**. All three are longer than Fleet's 10,000-character limit for ad hoc scripts, so they must be saved scripts.
2. Run one on a single test host first, from the host page **Actions → Run script**, or:

```bash
fleetctl run-script --script-name emudhra-remediate-linux.sh --host <hostname>
```

3. For the rest, add the matching policy from [emudhra-policies.sql](/dirtyfrag-blog/code/emudhra-policies.sql) and attach the script as its **Run script** automation. Each policy passes only when neither compromised root is left in the system or fleetd bundle, so fixed hosts turn green on their own. A host that stays red is one where the script refused to change the agent bundle: its script output says why.

On Linux, restart long-running services after the bundle changes, because most programs read it only at start. Node.js, pip-installed certifi and container images carry their own copies: update or rebuild those.

To roll back, copy a `.pre-emudhra` backup over the file it came from. On Linux, also delete any `emudhra-*.pem` files the script added to the p11-kit blocklist directory, then re-run `update-ca-certificates` or `update-ca-trust`. On Windows, delete the added entries from **Untrusted Certificates** in `certlm.msc`.

## Verify

Two test hosts serve certificates from a compromised intermediate. One chains through the emSign root, the other through the Sectigo cross-sign. A protected client must refuse both.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://dv-g3b-emudhra.we-have-a-problem.com/
```

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

```powershell
Invoke-WebRequest https://dv-g3b-emudhra.we-have-a-problem.com/
```

A certificate error means protected. A `200` means that client still trusts the chain.

{{< figure src="images/before-after.svg" alt="Terminal output on an unpatched Ubuntu 22.04 host: before the fix, curl to both eMudhra test hosts returns hello and HTTP 200; the remediation script distrusts the roots and cleans the fleetd bundle; after the fix, curl fails with error 60 SSL certificate problem for both test hosts while github.com still returns 200" caption="Real output from one host, before and after running the Linux script." >}}

Re-run the query afterwards. The `root_in_ca_bundle`, `root_in_pem_bundle` and `fleetd_osquery_ca_bundle` rows should be gone.

## How this was validated

- **Queries:** every table and column was checked against [fleetdm.com/tables](https://fleetdm.com/tables/certificates). The queries ran live in osquery 5.24 on macOS and on Ubuntu 22.04 and 24.04, with Fleet's own `go_binaries` and `file_lines` table code loaded.
- **Linux script:** ran as root on Ubuntu 22.04 with a held 2021 bundle, Ubuntu 24.04, Debian 12, Rocky Linux 9, Fedora 44 and Alpine. Afterwards `openssl verify` rejected the forged chain and a second run changed nothing. An unreachable Fleet URL, and a Fleet URL that chains through a removed root, both left the agent bundle untouched. Arch Linux was not tested.
- **macOS script:** ran against copies of the real Apple and fleetd bundles. Apple's own `curl` reached the test host through the original bundle and was refused with the cleaned copy, while GitHub, Apple and PyPI still connected. A Fleet URL that chains through a removed root left the agent bundle untouched.
- **Windows script:** ran through Fleet on a real Windows host (Windows PowerShell 5.1 as SYSTEM). It added all 16 intermediates to Untrusted Certificates, Windows reported `ExplicitDistrust` for 16 of 16, and the fleetd bundle was cleaned. That host pins its own Fleet certificate, so the Fleet-server chain check and both registry layouts were tested in PowerShell 7.4 instead.

## Sources

- [eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/): disclosure site, certificate list, test hosts and per-package fix versions
- [Mozilla Bugzilla 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449): timeline and root cause
- [Mozilla Security Blog](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/) and [Google](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/): browser-side response
- [The Hacker News](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html) and [BleepingComputer](https://www.bleepingcomputer.com/news/security/mozilla-google-apple-block-compromised-emudhra-ca-certificates/): vendor timeline
- [Go release history](https://go.dev/doc/devel/release), [Go crypto/x509](https://pkg.go.dev/crypto/x509), [Node.js CLI docs](https://nodejs.org/api/cli.html): runtime trust behavior
- [Ubuntu ca-certificates changelog](https://launchpad.net/ubuntu/+source/ca-certificates/+changelog): Ubuntu fix
- [fleetdm/fleet#56173](https://github.com/fleetdm/fleet/pull/56173): emSign root removed from the fleetd bundle
