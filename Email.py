#!/usr/bin/env python3
"""
qualys_cve_outlook_drafter.py
─────────────────────────────────────────────────────────────────────────────
GAV-ONLY — No KnowledgeBase, no CSAM access required.

Prompts for a CVE ID → searches Qualys GAV (Global AssetView) for every
host that has the CVE detected → extracts the vulnerable software name,
installed version, and recommended fix version from each host's embedded
vulnerability scan data → creates one Outlook DRAFT email per host via
win32com (pywin32).

Open Outlook → Drafts folder, add recipient email addresses, then send.

Dependencies
────────────
    pip install requests pywin32

Usage
─────
    python qualys_cve_outlook_drafter.py
    → Enter CVE ID : CVE-2024-12345

Data sources  (GAV only)
─────────────────────────
    • POST /qps/rest/2.0/search/am/hostasset   — CVE-filtered host list
      Response fields used per HostAsset:
        · id, dnsHostName, fqdn, netbiosName, address, os
        · vuln.list.HostAssetVuln  → qid, title, severity, results, cveIds
        · softwareListData.list.HostAssetSoftware  → name, version

CHANGES FROM ORIGINAL
─────────────────────
Bug 1 — 400 CLIENT ERROR (root cause)
    _build_gav_xml: filter field was "vuln.vulnerability.cveId" which does
    not exist in the GAV schema and causes Qualys to reject the request.
    Fixed to "vuln.cveId". Operator changed from EQUALS → CONTAINS because
    some Qualys tenants store multiple CVEs as a delimited string in the
    field rather than a single exact value.
    Also changed ET.tostring(encoding="utf-8") → encoding="unicode" to
    remove the <?xml …?> declaration prefix that some Qualys instances
    reject as a 400.

Bug 2 — SILENT CVE MISMATCH (no match ever found in _parse_host)
    The old code searched for lowercase <cveId> elements. Qualys GAV
    responses use three different formats depending on API version:
      · <CveId><cve>CVE-2024-123</cve></CveId>  (nested, most common)
      · <cveId>CVE-2024-123</cveId>             (flat text, older schema)
      · <cveIds>CVE-2024-123,CVE-2024-456</cveIds>  (comma-separated text)
    The fixed parser handles all three formats.

Bug 3 — MISSING HEADER on QPS calls
    "X-Requested-With" is required by most Qualys platform endpoints
    (both FO and QPS REST) to signal a non-browser API client.
    Added to qps_headers.
"""

import re
import sys
import logging
from datetime import datetime

import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

# ── win32com / pywin32 guard ───────────────────────────────────────────────
try:
    import win32com.client
    import pythoncom
except ImportError:
    sys.exit(
        "\n[ERROR] pywin32 is not installed.\n"
        "  Fix : pip install pywin32\n"
        "  Note: Microsoft Outlook must be installed on this machine.\n"
    )

# ============================================================
# CONFIGURATION
# ============================================================
USERNAME   = "your_qualys_username"
PASSWORD   = "your_qualys_password"
CERT_PATH  = "/path/to/your/corporate_cert.pem"  # or False to skip SSL verify
BASE_URL   = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE  = 100   # GAV results per paginated page
# ============================================================

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("QualysCVEMailer")

# ── Severity labels & header colours ─────────────────────────────────────────
_SEVERITY = {
    "5": "Critical",
    "4": "High",
    "3": "Medium",
    "2": "Low",
    "1": "Informational",
}
_SEV_COLOR = {
    "5": "#b91c1c",   # red
    "4": "#c2410c",   # orange-red
    "3": "#b45309",   # amber
    "2": "#1d4ed8",   # blue
    "1": "#374151",   # grey
}

# ── Version extraction — compiled once at module level ────────────────────────
_RE_INSTALLED = re.compile(
    r"(?:installed(?:\s+(?:version|package))?|"
    r"package\s+installed|"
    r"detected(?:\s+version)?|"
    r"version\s+detected|"
    r"running(?:\s+version)?|"
    r"current(?:\s+version)?|"
    r"found\s*:)"
    r"[\s:]*"
    r"([\d][\w.\-]+)",
    re.IGNORECASE,
)

_RE_FIXED = re.compile(
    r"(?:fixed(?:\s+(?:version|package))?|"
    r"package\s+(?:updated|fixed)|"
    r"upgrade\s+to|"
    r"update\s+to|"
    r"patched\s+in|"
    r"resolved\s+in|"
    r"apply\s+(?:patch|fix)|"
    r"remediat\w+\s+(?:version|to))"
    r"[\s:]*"
    r"([\d][\w.\-]+)",
    re.IGNORECASE,
)

_RE_TITLE_STOP = re.compile(
    r"\s+(?:multiple|remote|code|execution|elevation|privilege|denial|of|"
    r"service|injection|bypass|disclosure|information|security|update|"
    r"patch|rce|vulnerability|vulnerabilities)\b.*",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# CVE ID prompt
# ─────────────────────────────────────────────────────────────────────────────

def prompt_cve_id() -> str:
    """
    Interactive prompt that validates CVE-YEAR-NUMBER format.
    Loops until the user enters a correctly formatted CVE ID.
    """
    print()
    print("=" * 64)
    print("  Qualys CVE → Outlook Draft Email Generator  (GAV-only)")
    print("=" * 64)
    while True:
        raw   = input("\n  Enter CVE ID (e.g. CVE-2024-12345) : ").strip().upper()
        parts = raw.split("-")
        if (
            len(parts) >= 3
            and parts[0] == "CVE"
            and parts[1].isdigit()
            and parts[2].isdigit()
        ):
            print(f"  ✓  CVE ID accepted : {raw}\n")
            return raw
        print("  ✗  Invalid. Format must be  CVE-YEAR-NUMBER  e.g. CVE-2024-12345")


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class QualysCVEMailer:

    def __init__(self, cve_id: str):
        self.cve_id      = cve_id.strip().upper()
        self.base_url    = BASE_URL.rstrip("/")
        self.session     = requests.Session()
        self.auth        = HTTPBasicAuth(USERNAME, PASSWORD)
        # BUG 3 FIX: X-Requested-With is required by all Qualys API endpoints
        # (both FO and QPS REST) to identify non-browser API clients.
        self.fo_headers  = {"X-Requested-With": "Python"}
        self.qps_headers = {
            "Content-Type":    "application/xml",
            "Accept":          "application/xml",
            "X-Requested-With": "Python",          # ← added (was missing)
        }

    # ── Authentication ────────────────────────────────────────────────────

    def login(self):
        r = self.session.post(
            f"{self.base_url}/api/2.0/fo/session/",
            headers=self.fo_headers,
            data={"action": "login", "username": USERNAME, "password": PASSWORD},
            verify=CERT_PATH,
        )
        r.raise_for_status()
        if "QualysSession" not in self.session.cookies:
            raise RuntimeError("Login failed — no QualysSession cookie returned.")
        log.info("Logged in successfully.")

    def logout(self):
        try:
            self.session.post(
                f"{self.base_url}/api/2.0/fo/session/",
                headers=self.fo_headers,
                data={"action": "logout"},
                verify=CERT_PATH,
            )
        except Exception:
            pass
        log.info("Logged out.")

    # ── Step 1 : GAV search — hosts with this CVE ─────────────────────────
    #
    # BUG 1 FIX SUMMARY
    # ─────────────────
    # OLD (causes 400): field="vuln.vulnerability.cveId"  operator="EQUALS"
    #   "vuln.vulnerability.cveId" is not a valid GAV schema field. The extra
    #   ".vulnerability." nesting does not exist — Qualys rejects it with 400.
    #
    # NEW (correct):    field="vuln.cveId"  operator="CONTAINS"
    #   "vuln.cveId" is the documented GAV asset filter field for CVE matching.
    #   CONTAINS is used instead of EQUALS because some tenants store multiple
    #   CVEs as a comma-separated string in that field; CONTAINS handles both
    #   single and multi-value storage safely.
    #
    # ALSO FIXED: ET.tostring(encoding="utf-8") produced a bytes object
    #   prefixed with <?xml version='1.0' encoding='utf-8'?> which some
    #   Qualys platform versions reject as a 400 malformed request.
    #   Changed to encoding="unicode" which returns a clean str with no
    #   declaration prefix.

    def _build_gav_xml(self, offset: int) -> str:
        """
        Build paginated GAV ServiceRequest XML with the CVE ID filter.
        Returns a unicode str (no XML declaration) to avoid 400 errors on
        Qualys platforms that reject the declaration prefix.
        """
        root    = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        crit    = ET.SubElement(filters, "Criteria")
        # ↓ FIXED: was "vuln.vulnerability.cveId" (invalid → 400 error)
        crit.set("field", "vuln.cveId")
        # ↓ FIXED: CONTAINS handles both single-CVE and comma-delimited fields
        crit.set("operator", "CONTAINS")
        crit.text = self.cve_id
        prefs     = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text    = str(PAGE_SIZE)
        # ↓ FIXED: encoding="unicode" → returns str, no <?xml?> declaration
        return ET.tostring(root, encoding="unicode")

    def fetch_hosts_from_gav(self) -> list[ET.Element]:
        """
        Paginate through GAV and return all HostAsset XML elements that
        have the target CVE somewhere in their vulnerability list.

        Each returned element already contains:
          • Host identity fields (id, dnsHostName, address, os, …)
          • <vuln>           — full vulnerability list with results text
          • <softwareListData> — installed software inventory
        """
        url          = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset, page = 1, 1
        all_assets   = []

        log.info(f"[GAV] Searching for hosts with {self.cve_id} …")
        while True:
            log.info(f"  Page {page} (offset {offset}) …")
            r = self.session.post(
                url,
                headers=self.qps_headers,
                auth=self.auth,
                data=self._build_gav_xml(offset),
                verify=CERT_PATH,
            )
            if r.status_code == 400:
                # Surface the Qualys error message — far more useful than
                # a raw HTTPError traceback
                try:
                    err_root = ET.fromstring(r.content)
                    qerr = (
                        err_root.findtext(".//errorMessage")
                        or err_root.findtext(".//message")
                        or r.text[:300]
                    )
                except Exception:
                    qerr = r.text[:300]
                raise RuntimeError(
                    f"400 Bad Request from GAV API.\n"
                    f"  Qualys error : {qerr}\n"
                    f"  Check: BASE_URL platform matches your subscription region,\n"
                    f"         and that GAV / Asset Management is enabled on your account."
                )
            if r.status_code == 401:
                raise RuntimeError(
                    "401 Unauthorized — ensure 'API Access' and "
                    "'Asset Management' roles are enabled under Administration > Users."
                )
            r.raise_for_status()

            root       = ET.fromstring(r.content)
            page_hosts = root.findall(".//HostAsset")
            if not page_hosts:
                break

            all_assets.extend(page_hosts)
            log.info(f"    {len(page_hosts)} asset(s) on page | total so far: {len(all_assets)}")

            if root.findtext(".//hasMoreRecords") != "true":
                break
            offset += PAGE_SIZE
            page   += 1

        log.info(f"[GAV] Total hosts found with {self.cve_id}: {len(all_assets)}")
        return all_assets

    # ── Step 2 : Parse each HostAsset element ─────────────────────────────

    @staticmethod
    def _tx(el: ET.Element, path: str) -> str:
        """Safe text extractor — returns '' instead of None."""
        return (el.findtext(path) or "").strip()

    def _parse_host(self, asset: ET.Element) -> dict:
        """
        Extract host identity, the specific HostAssetVuln entry for this CVE,
        and the full software inventory from a <HostAsset> XML element.

        Returns
        -------
        {
          id, hostname, ip, fqdn, os, netbios,
          vuln: {qid, title, severity, results},
          software_list: [{name, version}, …]
        }
        """
        tx = lambda p: self._tx(asset, p)

        host = {
            "id":       tx("id"),
            "hostname": tx("dnsHostName") or tx("fqdn") or tx("netbiosName") or tx("address"),
            "ip":       tx("address"),
            "fqdn":     tx("fqdn"),
            "os":       tx("os") or tx("operatingSystem"),
            "netbios":  tx("netbiosName"),
        }

        # ── Find the HostAssetVuln entry that contains this CVE ───────────
        #
        # BUG 2 FIX: The old code only searched for lowercase <cveId> elements
        # which never matched because Qualys GAV uses three different formats:
        #
        #   Format A (most common — v2 schema):
        #     <cveIds><list><CveId><cve>CVE-2024-123</cve></CveId></list></cveIds>
        #
        #   Format B (flat element — older schema):
        #     <cveIds><list><cveId>CVE-2024-123</cveId></list></cveIds>
        #
        #   Format C (comma-separated text — legacy):
        #     <cveIds>CVE-2024-123,CVE-2024-456</cveIds>
        #
        # The fixed code handles all three so the correct vuln entry is always
        # found and the title/severity/results fields are populated in the email.

        vuln_data = {"qid": "", "title": "", "severity": "N/A", "results": ""}

        for vuln_el in asset.findall(".//HostAssetVuln"):
            cve_ids_in_entry: set[str] = set()

            # Format A: <CveId><cve>CVE-…</cve></CveId>  (v2 schema)
            for c in vuln_el.findall(".//CveId"):
                cve_text = (c.findtext("cve") or c.text or "").strip().upper()
                if cve_text:
                    cve_ids_in_entry.add(cve_text)

            # Format B: <cveId>CVE-…</cveId>  (older schema, flat text)
            for c in vuln_el.findall(".//cveId"):
                if c.text:
                    cve_ids_in_entry.add(c.text.strip().upper())

            # Format C: <cveIds>CVE-123,CVE-456</cveIds>  (legacy, comma-sep)
            cve_raw = (vuln_el.findtext("cveIds") or "").strip()
            if cve_raw and "<" not in cve_raw:   # plain text, not child XML
                cve_ids_in_entry.update(
                    x.strip().upper() for x in cve_raw.split(",") if x.strip()
                )

            if self.cve_id in cve_ids_in_entry:
                vuln_data = {
                    "qid":      (vuln_el.findtext("qid")      or "").strip(),
                    "title":    (vuln_el.findtext("title")    or "").strip(),
                    "severity": (vuln_el.findtext("severity") or "N/A").strip(),
                    "results":  (vuln_el.findtext("results")  or "").strip(),
                }
                break   # first matching vuln is sufficient

        # ── Collect full software inventory from softwareListData ─────────
        software_list = [
            {
                "name":    (sw.findtext("name")    or "").strip(),
                "version": (sw.findtext("version") or "").strip(),
            }
            for sw in asset.findall(".//HostAssetSoftware")
            if (sw.findtext("name") or "").strip()
        ]

        host["vuln"]          = vuln_data
        host["software_list"] = software_list
        return host

    # ── Step 3 : Extract software name, installed version, fix version ─────

    def _extract_software_info(self, vuln_data: dict, software_list: list) -> dict:
        """
        Determine the vulnerable software name, its installed version,
        and the recommended fix version using only data from GAV.

        Resolution order
        ────────────────
        Software name      : vuln.results → vuln.title prefix → sw inventory match
        Installed version  : vuln.results regex → sw inventory match
        Fix version        : vuln.results regex → token fallback → advisory note

        Returns
        -------
        {name, installed_version, fix_version, results_snippet}
        """
        results = vuln_data.get("results", "")
        title   = vuln_data.get("title",   "")

        # ── 1. Parse versions from scanner results text ───────────────────
        inst_m = _RE_INSTALLED.search(results)
        fix_m  = _RE_FIXED.search(results)
        inst_v = inst_m.group(1) if inst_m else ""
        fix_v  = fix_m.group(1)  if fix_m  else ""

        # Fallback: if no keyword-prefixed version found, pull version-like
        # tokens from the results. Use a stricter pattern (must contain a dot
        # or dash with digits on both sides) to avoid single-number false hits.
        if (not inst_v or not fix_v) and results:
            tokens = re.findall(r"\b\d+(?:[.\-]\d[\w.\-]*)+ \b", results)
            if not tokens:
                # Broader fallback for very short strings like "1.0.2k → 1.1.1l"
                tokens = re.findall(r"\b\d[\w.\-]{3,}\b", results)
            if tokens:
                if not inst_v and len(tokens) >= 1:
                    inst_v = tokens[0]
                if not fix_v  and len(tokens) >= 2:
                    fix_v  = tokens[-1]

        # ── 2. Derive software name hint from the vuln title ──────────────
        sw_hint = _RE_TITLE_STOP.sub("", title).strip() if title else ""

        # ── 3. Match hint against installed software inventory ────────────
        matched_sw = None
        if sw_hint and software_list:
            hint_lower = sw_hint.lower()
            words = sw_hint.split()
            for length in range(len(words), 0, -1):
                prefix = " ".join(words[:length]).lower()
                for sw in software_list:
                    sw_lower = sw["name"].lower()
                    if prefix in sw_lower or sw_lower in hint_lower:
                        matched_sw = sw
                        break
                if matched_sw:
                    break

        # ── 4. Resolve final values ───────────────────────────────────────
        final_name   = (matched_sw["name"] if matched_sw else sw_hint) or title[:70]
        final_inst_v = inst_v or (matched_sw["version"] if matched_sw else "") \
                       or "Version not extracted — see scan output below"
        final_fix_v  = fix_v \
                       or "Upgrade to latest — refer to vendor advisory"

        return {
            "name":              final_name,
            "installed_version": final_inst_v,
            "fix_version":       final_fix_v,
            "results_snippet":   results[:600] if results else "",
        }

    # ── Step 4 : Build HTML email body ────────────────────────────────────

    def _build_html_body(self, host: dict, sw_info: dict) -> str:
        """
        Returns a fully self-contained HTML email body.

        Sections
        ────────
        Banner (severity colour) → Host details → Vulnerability details →
        Software & fix version table → Raw scan output → Action steps → Footer
        """
        sev       = host["vuln"]["severity"]
        sev_label = _SEVERITY.get(sev, f"Severity {sev}")
        sev_color = _SEV_COLOR.get(sev, "#374151")
        hostname  = host["hostname"] or host["ip"] or host["id"]
        vuln_title = host["vuln"]["title"] or f"{self.cve_id} Vulnerability"
        now_str   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        scan_block_html = ""
        if sw_info["results_snippet"]:
            escaped = (
                sw_info["results_snippet"]
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            scan_block_html = f"""
        <tr>
          <td style="padding:0 32px 24px;">
            <p style="margin:0 0 8px;font-size:13px;font-weight:700;color:#1e293b;
                      text-transform:uppercase;letter-spacing:.6px;">
              Scanner Detection Output
            </p>
            <pre style="margin:0;background:#f8fafc;border:1px solid #e2e8f0;
                        border-left:4px solid {sev_color};border-radius:4px;
                        padding:14px 16px;font-size:12px;color:#334155;
                        white-space:pre-wrap;word-break:break-word;
                        font-family:Consolas,'Courier New',monospace;">{escaped}</pre>
          </td>
        </tr>"""

        def info_row(label: str, value: str, shade: bool) -> str:
            bg = ' style="background:#f8fafc;"' if shade else ""
            return (
                f'<tr{bg}>'
                f'<td style="padding:9px 14px;color:#64748b;font-weight:600;'
                f'width:160px;font-size:13px;white-space:nowrap;">{label}</td>'
                f'<td style="padding:9px 14px;color:#1e293b;font-size:13px;">{value}</td>'
                f"</tr>"
            )

        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#f1f5f9;
             font-family:Calibri,'Segoe UI',Arial,sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#f1f5f9;padding:28px 0;">
  <tr><td align="center">

  <table width="660" cellpadding="0" cellspacing="0"
         style="background:#ffffff;border-radius:10px;overflow:hidden;
                box-shadow:0 4px 20px rgba(0,0,0,.10);">

    <!-- ═══ BANNER ═══ -->
    <tr>
      <td style="background:{sev_color};padding:26px 32px 22px;">
        <p style="margin:0;color:rgba(255,255,255,.80);font-size:11px;
                  text-transform:uppercase;letter-spacing:1.2px;font-weight:600;">
          Security Notification &nbsp;·&nbsp; Action Required
        </p>
        <h1 style="margin:8px 0 0;color:#ffffff;font-size:21px;
                   font-weight:700;line-height:1.3;">
          {self.cve_id} &mdash; Vulnerability Detected
        </h1>
        <p style="margin:10px 0 0;color:rgba(255,255,255,.88);font-size:14px;">
          Severity:&nbsp;<strong>{sev_label}</strong>
          &nbsp;&nbsp;|&nbsp;&nbsp;
          Device:&nbsp;<strong>{hostname}</strong>
        </p>
      </td>
    </tr>

    <!-- ═══ INTRO ═══ -->
    <tr>
      <td style="padding:26px 32px 16px;">
        <p style="margin:0;color:#334155;font-size:14px;line-height:1.7;">
          Dear IT&nbsp;/&nbsp;Asset Owner,<br><br>
          The Vulnerability Management team has identified a
          <strong style="color:{sev_color};">{sev_label}</strong>-severity
          vulnerability (<strong>{self.cve_id}</strong>) on the device listed below.
          Please apply the recommended remediation at the earliest opportunity.
        </p>
      </td>
    </tr>

    <!-- ═══ HOST DETAILS ═══ -->
    <tr>
      <td style="padding:0 32px 24px;">
        <p style="margin:0 0 10px;font-size:13px;font-weight:700;color:#1e293b;
                  text-transform:uppercase;letter-spacing:.6px;
                  border-bottom:2px solid #e2e8f0;padding-bottom:8px;">
          Host Details
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;border:1px solid #e2e8f0;border-radius:6px;
                      overflow:hidden;">
          {info_row("Device Name",       hostname,             False)}
          {info_row("IP Address",        host["ip"]  or "—",  True)}
          {info_row("FQDN",              host["fqdn"] or "—", False)}
          {info_row("Operating System",  host["os"]   or "—", True)}
          {info_row("Qualys Asset ID",   host["id"],           False)}
        </table>
      </td>
    </tr>

    <!-- ═══ VULNERABILITY DETAILS ═══ -->
    <tr>
      <td style="padding:0 32px 24px;">
        <p style="margin:0 0 10px;font-size:13px;font-weight:700;color:#1e293b;
                  text-transform:uppercase;letter-spacing:.6px;
                  border-bottom:2px solid #e2e8f0;padding-bottom:8px;">
          Vulnerability Details
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;border:1px solid #e2e8f0;border-radius:6px;
                      overflow:hidden;">
          {info_row("CVE ID",
                    f'<strong style="color:{sev_color};">{self.cve_id}</strong>',
                    False)}
          {info_row("Title",    vuln_title, True)}
          {info_row("Severity",
                    f'<span style="background:{sev_color};color:#fff;padding:2px 12px;'
                    f'border-radius:12px;font-size:12px;font-weight:700;">'
                    f'{sev_label}</span>',
                    False)}
          {info_row("QID",      host["vuln"]["qid"] or "N/A", True)}
        </table>
      </td>
    </tr>

    <!-- ═══ SOFTWARE / VERSION TABLE ═══ -->
    <tr>
      <td style="padding:0 32px 24px;">
        <p style="margin:0 0 10px;font-size:13px;font-weight:700;color:#1e293b;
                  text-transform:uppercase;letter-spacing:.6px;
                  border-bottom:2px solid #e2e8f0;padding-bottom:8px;">
          Vulnerable Software &amp; Recommended Fix
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;border:1px solid #e2e8f0;
                      border-radius:6px;overflow:hidden;font-size:13px;">
          <tr style="background:#1e293b;">
            <th style="padding:11px 14px;text-align:left;color:#f8fafc;font-weight:600;
                       font-size:12px;letter-spacing:.5px;width:30%;">
              Software Name
            </th>
            <th style="padding:11px 14px;text-align:left;color:#f8fafc;font-weight:600;
                       font-size:12px;letter-spacing:.5px;width:30%;">
              Installed Version
            </th>
            <th style="padding:11px 14px;text-align:left;color:#f8fafc;font-weight:600;
                       font-size:12px;letter-spacing:.5px;width:30%;">
              Recommended Version
            </th>
            <th style="padding:11px 14px;text-align:center;color:#f8fafc;font-weight:600;
                       font-size:12px;letter-spacing:.5px;">
              Status
            </th>
          </tr>
          <tr style="background:#fff7f7;">
            <td style="padding:13px 14px;color:#1e293b;font-weight:600;
                       border-top:1px solid #e2e8f0;">
              {sw_info["name"]}
            </td>
            <td style="padding:13px 14px;color:#b91c1c;font-weight:700;
                       font-family:Consolas,'Courier New',monospace;
                       border-top:1px solid #e2e8f0;">
              {sw_info["installed_version"]}
            </td>
            <td style="padding:13px 14px;color:#15803d;font-weight:700;
                       font-family:Consolas,'Courier New',monospace;
                       border-top:1px solid #e2e8f0;">
              {sw_info["fix_version"]}
            </td>
            <td style="padding:13px 14px;text-align:center;border-top:1px solid #e2e8f0;">
              <span style="background:#fee2e2;color:#b91c1c;padding:3px 10px;
                           border-radius:12px;font-size:11px;font-weight:700;
                           border:1px solid #fca5a5;white-space:nowrap;">
                &#9888; VULNERABLE
              </span>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    {scan_block_html}

    <!-- ═══ REQUIRED ACTIONS ═══ -->
    <tr>
      <td style="padding:0 32px 26px;">
        <p style="margin:0 0 14px;font-size:13px;font-weight:700;color:#1e293b;
                  text-transform:uppercase;letter-spacing:.6px;
                  border-bottom:2px solid #e2e8f0;padding-bottom:8px;">
          Required Actions
        </p>
        <table cellpadding="0" cellspacing="0" style="font-size:13px;color:#334155;">
          <tr>
            <td style="vertical-align:top;padding:5px 0;">
              <span style="display:inline-block;background:{sev_color};color:#fff;
                           border-radius:50%;width:22px;height:22px;text-align:center;
                           line-height:22px;font-size:12px;font-weight:700;
                           margin-right:12px;flex-shrink:0;">1</span>
            </td>
            <td style="padding:5px 0;line-height:1.6;">
              Upgrade <strong>{sw_info["name"]}</strong> from
              <code style="background:#f1f5f9;padding:1px 7px;border-radius:3px;
                           font-size:12px;color:#b91c1c;">{sw_info["installed_version"]}</code>
              to
              <code style="background:#f1f5f9;padding:1px 7px;border-radius:3px;
                           font-size:12px;color:#15803d;">{sw_info["fix_version"]}</code>
              or the latest available version.
            </td>
          </tr>
          <tr>
            <td style="vertical-align:top;padding:5px 0;">
              <span style="display:inline-block;background:{sev_color};color:#fff;
                           border-radius:50%;width:22px;height:22px;text-align:center;
                           line-height:22px;font-size:12px;font-weight:700;
                           margin-right:12px;">2</span>
            </td>
            <td style="padding:5px 0;line-height:1.6;">
              Reply to this email with the date of remediation and the method used.
            </td>
          </tr>
          <tr>
            <td style="vertical-align:top;padding:5px 0;">
              <span style="display:inline-block;background:{sev_color};color:#fff;
                           border-radius:50%;width:22px;height:22px;text-align:center;
                           line-height:22px;font-size:12px;font-weight:700;
                           margin-right:12px;">3</span>
            </td>
            <td style="padding:5px 0;line-height:1.6;">
              A follow-up vulnerability scan will be run to confirm the patch.
            </td>
          </tr>
        </table>
        <p style="margin:18px 0 0;color:#475569;font-size:13px;
                  background:#f8fafc;padding:12px 16px;border-radius:6px;
                  border-left:3px solid {sev_color};">
          If this finding is a false positive, or the device has already been
          patched, please reply with supporting evidence for record update.
          &nbsp;|&nbsp; SLA for <strong>{sev_label}</strong> findings:
          <strong>[ADD YOUR SLA HERE]</strong>
        </p>
      </td>
    </tr>

    <!-- ═══ SIGN-OFF ═══ -->
    <tr>
      <td style="padding:0 32px 28px;">
        <p style="margin:0;font-size:13px;color:#334155;line-height:1.8;">
          Regards,<br>
          <strong>Security / Vulnerability Management Team</strong><br>
          <em>[Organisation Name]</em>
        </p>
      </td>
    </tr>

    <!-- ═══ FOOTER ═══ -->
    <tr>
      <td style="background:#f8fafc;padding:13px 32px;
                 border-top:1px solid #e2e8f0;">
        <p style="margin:0;color:#94a3b8;font-size:11px;line-height:1.6;">
          Auto-generated from Qualys Global AssetView (GAV) &nbsp;|&nbsp;
          {now_str} &nbsp;|&nbsp;
          Do not reply to this automated message — contact the team directly.
        </p>
      </td>
    </tr>

  </table>

  </td></tr>
</table>

</body>
</html>"""
        return html

    # ── Step 5 : Create Outlook draft via win32com ────────────────────────

    @staticmethod
    def _create_outlook_draft(
        outlook_app,
        subject:   str,
        html_body: str,
        hostname:  str,
    ) -> bool:
        """
        Create one Outlook MailItem draft and save it to the Drafts folder.
        The To field is intentionally left blank — user fills it before sending.
        """
        try:
            mail          = outlook_app.CreateItem(0)   # 0 = olMailItem
            mail.Subject  = subject
            mail.HTMLBody = html_body
            mail.Save()
            log.info(f"  ✓  Draft saved : {hostname}")
            return True
        except Exception as exc:
            log.error(f"  ✗  Draft failed for {hostname}: {exc}")
            return False

    # ── Orchestrator ───────────────────────────────────────────────────────

    def run(self):
        """
        Full pipeline:
          login → GAV search → parse each host → extract software/version →
          build HTML email → create Outlook draft → logout
        """
        self.login()
        try:
            assets = self.fetch_hosts_from_gav()
            if not assets:
                log.warning(
                    "No hosts returned from GAV for this CVE.\n"
                    "  • Verify that vulnerability scanning is active and "
                    "scan results are visible in GAV.\n"
                    "  • Confirm the CVE ID is correctly formatted.\n"
                    "  • If zero results persist, try changing the filter operator\n"
                    "    in _build_gav_xml() from CONTAINS to EQUALS, or check\n"
                    "    Qualys Administration > API > Asset Management is enabled."
                )
                return

            log.info(f"\n[Outlook] Connecting to Outlook via win32com …")
            pythoncom.CoInitialize()
            try:
                outlook_app = win32com.client.Dispatch("Outlook.Application")
            except Exception as exc:
                log.error(
                    f"Cannot connect to Outlook: {exc}\n"
                    "Ensure Microsoft Outlook is installed and your profile is set up."
                )
                return

            log.info(f"[Outlook] Creating {len(assets)} draft email(s) …")
            ok_count, fail_count = 0, 0

            for asset in assets:
                host     = self._parse_host(asset)
                hostname = host["hostname"] or host["ip"] or host["id"]
                sw_info  = self._extract_software_info(
                    host["vuln"], host["software_list"]
                )

                sev_label = _SEVERITY.get(host["vuln"]["severity"], "Unknown")
                subject   = (
                    f"[ACTION REQUIRED] {self.cve_id} — "
                    f"{sev_label} Vulnerability on {hostname}"
                )
                html_body = self._build_html_body(host, sw_info)

                success = self._create_outlook_draft(
                    outlook_app, subject, html_body, hostname
                )
                ok_count   += 1 if success else 0
                fail_count += 0 if success else 1

            print()
            print("=" * 64)
            print(f"  {ok_count} Outlook draft(s) created successfully.")
            if fail_count:
                print(f"  {fail_count} draft(s) failed — review log output above.")
            print("=" * 64)
            print("  Open Outlook → Drafts folder.")
            print("  Add the recipient's email address to each draft, then send.")
            print("=" * 64)
            print()

        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
            self.logout()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cve_id = prompt_cve_id()
    QualysCVEMailer(cve_id).run()
