#!/usr/bin/env python3
"""Generate a consistent 1200x630 cover.svg for every post (security + AI look).

Usage: python3 scripts/gen_covers.py   (run from the repo root)
Writes content/posts/<slug>/cover.svg and a copy to assets/covers/<slug>.svg
(the home page resolves card images from global assets).
"""
import sys, textwrap
from pathlib import Path
from xml.sax.saxutils import escape

POSTS = {
  "agentic-detector": ("AI · OSQUERY", "Seeing the AI Layer", "Detect agents, MCP servers and IDE plugins on every endpoint", "#22d3ee", "ai"),
  "amcache-in-sql": ("DFIR · WINDOWS", "The Amcache gap, closed", "Seven SQL tables for live Windows forensics", "#a78bfa", "database"),
  "clickfix-copypaste-fleet-detections": ("THREAT BRIEF", "ClickFix: copy/paste social engineering", "Five-stage attack flow and a Fleet detection pack", "#fb923c", "clipboard"),
  "cve-2026-98432-linux-tcp-uaf-fleet": ("CVE · LINUX KERNEL", "CVE-2026-98432", "TCP use-after-free: find it, mitigate it, auto-remove it", "#f87171", "chip"),
  "emudhra-ca-compromise-fleet": ("PKI · TRUST STORES", "eMudhra CA key compromise", "Fix the trust stores your browser does not cover", "#fbbf24", "cert"),
  "fleet-kever-agent-upgrade-runbook": ("AI · FLEET MCP", "One agent, one fleet, one reboot", "A kernel KEV wave, driven by MCP and a local LLM", "#22d3ee", "ai"),
  "fleet-mcp-manifesto": ("AI · FLEET MCP", "A Fleet MCP manifesto", "Endpoint risk and threat hunting, in plain English", "#34d399", "chat"),
  "http2shell-brotli-fleet": ("CVE · SUPPLY CHAIN", "HTTP2Shell: Brotli", "Hunt every vulnerable Brotli copy across the fleet", "#fb7185", "packets"),
  "mini-shai-hulud-tanstack-supply-chain": ("SUPPLY CHAIN · NPM", "Mini Shai-Hulud", "Detecting a live npm worm with Fleet", "#a3e635", "package"),
  "notepad-plus-plus-shortcuts-bypass-fleet": ("VULN MGMT · WINDOWS", "Notepad++ trusted-directory bypass", "GHSA-p58x-r3c9-x9p6, portable copies included", "#38bdf8", "document"),
  "one-control-plane-three-operating-systems": ("FLEET · MDM · COMPLIANCE", "One control plane, three operating systems", "Labels, profiles and policies across Windows, macOS and Linux", "#818cf8", "layers"),
  "pre-cve-response-with-fleet": ("INCIDENT RESPONSE", "Pre-CVE threat response", "A Dirty Frag walkthrough with Fleet", "#f472b6", "shield"),
  "shadow-earth-053-fleet-detections": ("THREAT INTEL", "SHADOW-EARTH-053", "Kill chain, Diamond Model and validated Fleet queries", "#e879f9", "radar"),
  "vibe-hunting-clickfix-fleet-mcp-atc": ("AI · THREAT HUNTING", "Vibe hunting", "Autonomous ClickFix hunting with fleet-mcp and ATC", "#2dd4bf", "target"),
}

def motif(kind, a):
    s = f'stroke="{a}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"'
    f = f'fill="{a}"'
    if kind == "ai":
        pts = [(0,-95),(-90,-30),(90,-30),(-55,80),(55,80),(0,0)]
        e = [(0,1),(0,2),(1,3),(2,4),(3,4),(5,0),(5,1),(5,2),(5,3),(5,4),(1,2)]
        o = "".join(f'<line x1="{pts[i][0]}" y1="{pts[i][1]}" x2="{pts[j][0]}" y2="{pts[j][1]}" {s} opacity=".55"/>' for i,j in e)
        o += "".join(f'<circle cx="{x}" cy="{y}" r="{16 if i<5 else 26}" fill="#0b1220" {s}/>' for i,(x,y) in enumerate(pts))
        return o + f'<circle cx="0" cy="0" r="9" {f}/>'
    if kind == "database":
        return (f'<ellipse cx="0" cy="-80" rx="90" ry="28" {s}/><path d="M-90 -80v160c0 16 40 28 90 28s90-12 90-28v-160" {s}/>'
                f'<path d="M-90 -27c0 16 40 28 90 28s90-12 90-28M-90 27c0 16 40 28 90 28s90-12 90-28" {s} opacity=".6"/>')
    if kind == "clipboard":
        return (f'<rect x="-80" y="-95" width="160" height="200" rx="18" {s}/><rect x="-35" y="-115" width="70" height="36" rx="10" fill="#0b1220" {s}/>'
                f'<path d="M-45 -20l30 24-30 24M5 38h45" {s}/>')
    if kind == "chip":
        pins = "".join(f'<path d="M{x} -85v-30M{x} 85v30M-85 {x}h-30M85 {x}h30" {s} opacity=".6"/>' for x in (-45,0,45))
        return (pins + f'<rect x="-85" y="-85" width="170" height="170" rx="20" {s}/><rect x="-42" y="-42" width="84" height="84" rx="10" {s} opacity=".6"/>'
                f'<path d="M-14 6l14-16 14 16M0 -10v32" {s}/>')
    if kind == "cert":
        return (f'<rect x="-105" y="-80" width="210" height="150" rx="16" {s}/><path d="M-70 -35h90M-70 0h60M-70 30h40" {s} opacity=".6"/>'
                f'<circle cx="55" cy="28" r="30" fill="#0b1220" {s}/><path d="M42 55l-12 48 25-14 25 14-12-48" {s}/>')
    if kind == "chat":
        return (f'<path d="M-105 -80h210a12 12 0 0 1 12 12v112a12 12 0 0 1-12 12h-120l-50 44v-44h-40a12 12 0 0 1-12-12v-112a12 12 0 0 1 12-12z" {s}/>'
                f'<path d="M-68 -30h95M-68 6h135M-68 42h60" {s} opacity=".7"/><circle cx="62" cy="-30" r="7" {f}/>')
    if kind == "packets":
        return (f'<rect x="-100" y="-80" width="76" height="76" rx="10" {s}/><rect x="24" y="-80" width="76" height="76" rx="10" {s} opacity=".6"/>'
                f'<rect x="-50" y="28" width="100" height="76" rx="10" {s}/><path d="M-62 -42h24M62 -42h-24M-62 -42l12 12M-62 -42l12-12M0 -4v26M0 22l-9-10M0 22l9-10" {s}/>')
    if kind == "package":
        return (f'<path d="M0 -105l90 45v110l-90 45-90-45v-110z" {s}/><path d="M-90 -60l90 45 90-45M0 -15v105" {s} opacity=".6"/>'
                f'<path d="M-45 -82l90 45" {s} opacity=".6"/><circle cx="62" cy="62" r="24" fill="#0b1220" {s}/><path d="M52 62h20M62 52v20" {s} transform="rotate(45 62 62)"/>')
    if kind == "document":
        return (f'<path d="M-70 -105h92l48 48v162h-140z" {s}/><path d="M22 -105v48h48" {s} opacity=".6"/>'
                f'<path d="M-40 -20h80M-40 15h80M-40 50h50" {s} opacity=".7"/><circle cx="70" cy="75" r="26" fill="#0b1220" {s}/><path d="M89 94l22 22" {s}/>')
    if kind == "layers":
        return (f'<path d="M0 -95l105 48-105 48-105-48z" {s}/><path d="M-105 4l105 48 105-48" {s} opacity=".75"/>'
                f'<path d="M-105 56l105 48 105-48" {s} opacity=".5"/>')
    if kind == "shield":
        return (f'<path d="M0 -110l95 34v70c0 60-40 98-95 118-55-20-95-58-95-118v-70z" {s}/><path d="M-38 5l28 28 52-58" {s}/>')
    if kind == "radar":
        return (f'<circle r="105" {s}/><circle r="68" {s} opacity=".6"/><circle r="30" {s} opacity=".6"/>'
                f'<path d="M0 0L74 -74" {s}/><path d="M0 -105v210M-105 0h210" {s} opacity=".25"/><circle cx="-48" cy="38" r="9" {f}/><circle cx="52" cy="-8" r="9" {f}/>')
    if kind == "target":
        return (f'<circle r="105" {s}/><circle r="68" {s} opacity=".7"/><circle r="30" {s}/><circle r="8" {f}/>'
                f'<path d="M0 -130v40M0 90v40M-130 0h40M90 0h40" {s}/>')
    raise SystemExit(f"unknown motif {kind}")

def wrap(text, width, maxlines):
    lines = textwrap.wrap(text, width=width, break_long_words=False)
    if len(lines) > maxlines:
        raise SystemExit(f"too many lines for: {text!r} -> {lines}")
    return lines

def cover(slug):
    kicker, title, sub, acc, kind = POSTS[slug]
    tl = wrap(title, 21, 3)
    sl = wrap(sub, 44, 2)
    size = 60 if len(tl) < 3 else 54
    y0 = 250 if len(tl) == 1 else 225 if len(tl) == 2 else 200
    t = "".join(f'<tspan x="70" dy="{0 if i==0 else int(size*1.16)}">{escape(l)}</tspan>' for i,l in enumerate(tl))
    ty_end = y0 + int(size*1.16)*(len(tl)-1)
    st = "".join(f'<tspan x="70" dy="{0 if i==0 else 36}">{escape(l)}</tspan>' for i,l in enumerate(sl))
    desc = escape(f"{title}. {sub}.")
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="{desc}">
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b1220"/><stop offset="1" stop-color="#111c33"/></linearGradient>
<radialGradient id="glow" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="{acc}" stop-opacity=".34"/><stop offset="1" stop-color="{acc}" stop-opacity="0"/></radialGradient>
<pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#94a3b8" stroke-opacity=".08"/></pattern>
</defs>
<rect width="1200" height="630" fill="url(#bg)"/>
<rect width="1200" height="630" fill="url(#grid)"/>
<circle cx="930" cy="315" r="320" fill="url(#glow)"/>
<rect x="0" y="0" width="10" height="630" fill="{acc}"/>
<g font-family="ui-monospace,'JetBrains Mono',Menlo,Consolas,monospace">
<rect x="70" y="70" width="{34 + 14.8*len(kicker)}" height="40" rx="8" fill="{acc}" fill-opacity=".14" stroke="{acc}" stroke-opacity=".6"/>
<text x="87" y="97" font-size="20" font-weight="700" letter-spacing="2" fill="{acc}">{escape(kicker)}</text>
</g>
<g font-family="system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif">
<text x="70" y="{y0}" font-size="{size}" font-weight="800" fill="#f8fafc" letter-spacing="-1">{t}</text>
<text x="70" y="{ty_end + 70}" font-size="28" fill="#cbd5e1">{st}</text>
</g>
<g font-family="ui-monospace,'JetBrains Mono',Menlo,Consolas,monospace" font-size="20" fill="#94a3b8">
<text x="70" y="574">karmine's notes</text>
<text x="70" y="574" dx="190" fill="{acc}">/</text><text x="70" y="574" dx="210">fleet · osquery · detection engineering</text>
</g>
<g transform="translate(930 315)" fill="none">{motif(kind, acc)}</g>
</svg>
'''

if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "content/posts")
    assets = Path("assets/covers"); assets.mkdir(parents=True, exist_ok=True)
    for slug in POSTS:
        d = root / slug
        assert d.is_dir(), slug
        svg = cover(slug)
        (d / "cover.svg").write_text(svg)
        (assets / f"{slug}.svg").write_text(svg)
        print("wrote", slug)
