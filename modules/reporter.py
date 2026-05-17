"""
modules/reporter.py
Generates a unified HTML + JSON report from all module results.
The HTML report is self-contained (inline CSS, base64 screenshots).
"""

import os
import json
from datetime import datetime
from typing import Dict, Any


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedHawk Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
    --red: #f85149; --amber: #d29922; --green: #3fb950;
    --blue: #58a6ff; --purple: #bc8cff;
    --font: 'Courier New', Courier, monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font);
          font-size: 13px; line-height: 1.6; padding: 0; }}

  /* ── Header ── */
  header {{ background: var(--bg2); border-bottom: 1px solid var(--border);
            padding: 24px 32px; display: flex; align-items: center; gap: 20px; }}
  .logo {{ font-size: 28px; font-weight: 900; color: var(--red); letter-spacing: -1px; }}
  .meta {{ color: var(--muted); font-size: 12px; }}
  .meta b {{ color: var(--text); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 11px; font-weight: 700; margin-left: 8px; }}
  .badge-red {{ background: rgba(248,81,73,.15); color: var(--red);
               border: 1px solid rgba(248,81,73,.3); }}

  /* ── Layout ── */
  main {{ max-width: 1200px; margin: 0 auto; padding: 32px; }}
  section {{ margin-bottom: 40px; }}
  h2 {{ font-size: 15px; font-weight: 700; color: var(--blue);
        border-bottom: 1px solid var(--border); padding-bottom: 8px;
        margin-bottom: 16px; text-transform: uppercase; letter-spacing: .08em; }}

  /* ── Stat cards ── */
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px; margin-bottom: 32px; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border);
           border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-val {{ font-size: 32px; font-weight: 900; line-height: 1; color: var(--red); }}
  .stat-lbl {{ font-size: 11px; color: var(--muted); margin-top: 4px;
               text-transform: uppercase; letter-spacing: .06em; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; padding: 8px 12px; background: var(--bg3);
        color: var(--muted); font-weight: 700; text-transform: uppercase;
        font-size: 10px; letter-spacing: .08em; border-bottom: 1px solid var(--border); }}
  td {{ padding: 7px 12px; border-bottom: 1px solid var(--border);
        vertical-align: top; word-break: break-all; }}
  tr:hover td {{ background: var(--bg3); }}
  .port-open {{ color: var(--green); font-weight: 700; }}
  .vuln {{ color: var(--red); font-weight: 700; }}
  .tag {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
          font-size: 10px; margin: 1px; }}
  .tag-green {{ background: rgba(63,185,80,.15); color: var(--green);
                border: 1px solid rgba(63,185,80,.3); }}
  .tag-blue  {{ background: rgba(88,166,255,.12); color: var(--blue);
                border: 1px solid rgba(88,166,255,.3); }}
  .tag-red   {{ background: rgba(248,81,73,.12);  color: var(--red);
                border: 1px solid rgba(248,81,73,.3); }}

  /* ── Code / banners ── */
  pre {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 4px;
        padding: 8px; font-size: 11px; overflow-x: auto; color: var(--muted);
        white-space: pre-wrap; word-break: break-all; max-height: 80px;
        overflow-y: auto; }}

  /* ── Screenshots ── */
  .screenshots {{ display: grid;
                  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                  gap: 16px; }}
  .ss-card {{ background: var(--bg2); border: 1px solid var(--border);
              border-radius: 8px; overflow: hidden; }}
  .ss-card img {{ width: 100%; display: block; height: 180px; object-fit: cover;
                  object-position: top; }}
  .ss-url {{ padding: 8px 12px; font-size: 11px; color: var(--muted);
             border-top: 1px solid var(--border); word-break: break-all; }}

  /* ── Misc ── */
  .empty {{ color: var(--muted); font-style: italic; padding: 8px 0; font-size: 12px; }}
  .host-section {{ margin-bottom: 24px; }}
  .host-label {{ font-size: 12px; color: var(--amber); margin-bottom: 8px;
                 font-weight: 700; }}
  footer {{ text-align: center; color: var(--muted); font-size: 11px;
            padding: 24px; border-top: 1px solid var(--border); margin-top: 48px; }}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">&#9900; RedHawk</div>
    <div class="meta" style="margin-top:6px">
      <b>Target:</b> {target} &nbsp;|&nbsp;
      <b>Started:</b> {started} &nbsp;|&nbsp;
      <b>Finished:</b> {finished}
      <span class="badge badge-red">CONFIDENTIAL</span>
    </div>
  </div>
</header>

<main>

<!-- ── Summary stats ── -->
<div class="stats">
  <div class="stat"><div class="stat-val">{n_subdomains}</div><div class="stat-lbl">Subdomains</div></div>
  <div class="stat"><div class="stat-val">{n_open_ports}</div><div class="stat-lbl">Open Ports</div></div>
  <div class="stat"><div class="stat-val">{n_vulns}</div><div class="stat-lbl">CVEs (Shodan)</div></div>
  <div class="stat"><div class="stat-val">{n_emails}</div><div class="stat-lbl">Emails</div></div>
  <div class="stat"><div class="stat-val">{n_screenshots}</div><div class="stat-lbl">Screenshots</div></div>
</div>

<!-- ── Subdomains ── -->
<section>
  <h2>&#127758; Subdomain Enumeration</h2>
  {subdomains_html}
</section>

<!-- ── Port Scan ── -->
<section>
  <h2>&#128268; Port Scan &amp; Service Fingerprinting</h2>
  {ports_html}
</section>

<!-- ── Shodan ── -->
<section>
  <h2>&#128225; Shodan Passive Intelligence</h2>
  {shodan_html}
</section>

<!-- ── OSINT ── -->
<section>
  <h2>&#128270; OSINT (theHarvester)</h2>
  {osint_html}
</section>

<!-- ── Screenshots ── -->
<section>
  <h2>&#128247; Web Asset Screenshots</h2>
  {screenshots_html}
</section>

</main>

<footer>Generated by RedHawk &mdash; {now} &mdash; For authorized use only.</footer>
</body>
</html>
"""


class Reporter:
    def __init__(self, results: Dict[str, Any], out_dir: str):
        self.r = results
        self.out_dir = out_dir

    # ── Section renderers ──────────────────────────────────────────────────────

    def _subdomains_html(self) -> str:
        subs = self.r.get("subdomains", [])
        if not subs:
            return '<p class="empty">No subdomains discovered.</p>'
        rows = "".join(
            f"<tr><td>{i+1}</td><td>{h}</td></tr>"
            for i, h in enumerate(sorted(subs))
        )
        return f"""
        <table>
          <thead><tr><th>#</th><th>Hostname</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _ports_html(self) -> str:
        ports = self.r.get("ports", {})
        if not ports:
            return '<p class="empty">No port data collected.</p>'
        html = []
        for host, services in ports.items():
            rows = ""
            for s in sorted(services, key=lambda x: x["port"]):
                banner = s.get("banner", "").replace("<", "&lt;").replace(">", "&gt;")
                banner_html = f"<pre>{banner}</pre>" if banner else ""
                rows += (
                    f"<tr>"
                    f"<td class='port-open'>{s['port']}</td>"
                    f"<td>tcp</td>"
                    f"<td>{s.get('service','')}</td>"
                    f"<td>{banner_html}</td>"
                    f"</tr>"
                )
            html.append(f"""
            <div class="host-section">
              <div class="host-label">&#9658; {host}</div>
              <table>
                <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Banner</th></tr></thead>
                <tbody>{rows}</tbody>
              </table>
            </div>""")
        return "".join(html)

    def _shodan_html(self) -> str:
        shodan = self.r.get("shodan", {})
        if not shodan or shodan.get("error"):
            return '<p class="empty">No Shodan data (API key required).</p>'
        hosts = shodan.get("hosts", [])
        if not hosts:
            return '<p class="empty">No Shodan results.</p>'
        rows = ""
        for h in hosts:
            vulns = h.get("vulns", [])
            vuln_html = " ".join(
                f"<span class='tag tag-red'>{v}</span>" for v in vulns
            ) or "—"
            ports = ", ".join(str(p) for p in h.get("ports", []))
            rows += (
                f"<tr>"
                f"<td>{h.get('ip','')}</td>"
                f"<td>{h.get('org','')}</td>"
                f"<td>{h.get('country','')}</td>"
                f"<td>{h.get('os','') or '—'}</td>"
                f"<td>{ports}</td>"
                f"<td>{vuln_html}</td>"
                f"</tr>"
            )
        return f"""
        <table>
          <thead><tr><th>IP</th><th>Org</th><th>Country</th><th>OS</th><th>Ports</th><th>CVEs</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _osint_html(self) -> str:
        osint = self.r.get("osint", {})
        if not osint:
            return '<p class="empty">No OSINT data collected.</p>'
        emails = osint.get("emails", [])
        hosts  = osint.get("hosts", [])
        people = osint.get("linkedin_people", [])

        html = f"<p style='color:var(--muted);margin-bottom:12px'>Source: {osint.get('source','')}</p>"

        if emails:
            rows = "".join(f"<tr><td>{e}</td></tr>" for e in emails)
            html += f"""
            <div class="host-section">
              <div class="host-label">Email Addresses ({len(emails)})</div>
              <table><thead><tr><th>Address</th></tr></thead><tbody>{rows}</tbody></table>
            </div>"""

        if hosts:
            rows = "".join(f"<tr><td>{h}</td></tr>" for h in hosts)
            html += f"""
            <div class="host-section" style="margin-top:16px">
              <div class="host-label">Hosts ({len(hosts)})</div>
              <table><thead><tr><th>Host</th></tr></thead><tbody>{rows}</tbody></table>
            </div>"""

        if people:
            rows = "".join(f"<tr><td>{p}</td></tr>" for p in people)
            html += f"""
            <div class="host-section" style="margin-top:16px">
              <div class="host-label">LinkedIn People ({len(people)})</div>
              <table><thead><tr><th>Name</th></tr></thead><tbody>{rows}</tbody></table>
            </div>"""

        if not (emails or hosts or people):
            html += '<p class="empty">No data returned.</p>'

        return html

    def _screenshots_html(self) -> str:
        shots = self.r.get("screenshots", [])
        if not shots:
            return '<p class="empty">No screenshots captured. Ensure chromium-browser is installed.</p>'
        cards = ""
        for s in shots:
            b64 = s.get("base64", "")
            if b64:
                img_src = f"data:image/png;base64,{b64}"
                cards += f"""
                <div class="ss-card">
                  <img src="{img_src}" alt="{s['url']}" loading="lazy">
                  <div class="ss-url">{s['url']}</div>
                </div>"""
        return f'<div class="screenshots">{cards}</div>' if cards else \
               '<p class="empty">Screenshot files not found.</p>'

    # ── Public entry ──────────────────────────────────────────────────────────

    def generate(self) -> str:
        meta = self.r.get("meta", {})
        target = meta.get("target", "unknown")
        n_subs = len(self.r.get("subdomains", []))
        n_ports = sum(len(v) for v in self.r.get("ports", {}).values())
        n_vulns = self.r.get("shodan", {}).get("total_vulns", 0)
        n_emails = len(self.r.get("osint", {}).get("emails", []))
        n_ss = len(self.r.get("screenshots", []))

        html = HTML_TEMPLATE.format(
            target=target,
            started=meta.get("started_at", "")[:19].replace("T", " "),
            finished=meta.get("finished_at", "")[:19].replace("T", " "),
            n_subdomains=n_subs,
            n_open_ports=n_ports,
            n_vulns=n_vulns,
            n_emails=n_emails,
            n_screenshots=n_ss,
            subdomains_html=self._subdomains_html(),
            ports_html=self._ports_html(),
            shodan_html=self._shodan_html(),
            osint_html=self._osint_html(),
            screenshots_html=self._screenshots_html(),
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        out_path = os.path.join(self.out_dir, "redhawk_report.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        return out_path
