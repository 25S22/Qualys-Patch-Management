#!/usr/bin/env python3
"""
qualys_cve_emailer.py
─────────────────────────────────────────────────────────────────
Prompts for a CVE ID, queries Qualys GAV for all affected hosts,
enriches each with installed-software version data from the VM
Detection API and KnowledgeBase, then writes one ready-to-send
draft email (.txt) per host into a timestamped output folder.

Usage
─────
    python qualys_cve_emailer.py
    → prompted: Enter CVE ID : CVE-2024-12345

Workflow
────────
    1. KnowledgeBase API  → CVE title, severity, solution, QIDs
    2. GAV API            → all hosts that have this CVE detected
    3. VM Detection API   → installed software version & scan output
    4. Build draft email  → per-host email with version table + fix
    5. Save .txt drafts   → draft_emails_<CVE>_<timestamp>/
"""

import os
import re
import sys
import logging
from collections import defaultdict
from datetime import datetime

import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

# ============================================================
# CONFIGURATION
# ============================================================
USERNAME   = "your_qualys_username"
PASSWORD   = "your_qualys_password"
CERT_PATH  = "/path/to/your/corporate_cert.pem"  # or False to skip SSL verify
BASE_URL   = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE  = 100   # GAV results per paginated page
DET_BATCH  = 50    # Host IDs per VM Detection API batch call
OUTPUT_DIR = "."   # Parent dir; script creates draft_emails_<CVE>_<ts>/ here
# ============================================================

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("QualysCVEMailer")

# ── Severity label map ────────────────────────────────────────────────────────
_SEVERITY = {
    "5": "Critical",
    "4": "High",
    "3": "Medium",
    "2": "Low",
    "1": "Informational",
}

# ── Version extraction patterns (compiled once at module level) ───────────────
#
# _RE_INSTALLED matches lines like:
#   "Package Installed: openssl-1.0.2k-21.el7.x86_64"
#   "Installed version: 2.4.50"
#   "Version detected: 7.4.3"
#
_RE_INSTALLED = re.compile(
    r"(?:installed(?:\s+(?:version|package))?|"
    r"detected(?:\s+version)?|"
    r"running(?:\s+version)?|"
    r"current(?:\s+version)?|"
    r"package\s+installed|"
    r"version\s+detected|"
    r"found\s*:)"
    r"[\s:]*"
    r"([\d][\w.\-]+)",
    re.IGNORECASE,
)

# _RE_FIXED matches lines like:
#   "Package Updated: openssl-1.0.2k-22.el7.x86_64"
#   "Upgrade to version 1.1.1l"
#   "Fixed version: 2.4.51"
#
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


# ─────────────────────────────────────────────────────────────────────────────
# CVE ID prompt
# ─────────────────────────────────────────────────────────────────────────────

def prompt_cve_id() -> str:
    """
    Interactive prompt that validates the standard CVE-YEAR-NUMBER format.
    Loops until a valid ID is entered.
    """
    print()
    print("=" * 62)
    print("  Qualys CVE Host Finder & Draft Email Generator")
    print("=" * 62)
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
        print("  ✗  Invalid format. Expected CVE-YEAR-NUMBER, e.g. CVE-2024-12345")


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class QualysCVEMailer:

    def __init__(self, cve_id: str):
        self.cve_id      = cve_id.strip().upper()
        self.base_url    = BASE_URL.rstrip("/")
        self.session     = requests.Session()
        self.auth        = HTTPBasicAuth(USERNAME, PASSWORD)
        self.fo_headers  = {"X-Requested-With": "Python"}
        self.qps_headers = {
            "Content-Type": "application/xml",
            "Accept":       "application/xml",
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

    # ── Step 1 : KnowledgeBase lookup ─────────────────────────────────────

    def get_vulnerability_info(self) -> dict:
        """
        Query the Qualys KnowledgeBase for CVE metadata:
        title, severity, diagnosis, solution text, affected software,
        and the QID(s) associated with this CVE.

        Returns a dict with keys:
            cve_id, qids, title, severity, diagnosis, solution, software_list
        """
        log.info(f"[KB] Querying KnowledgeBase for {self.cve_id} …")
        r = self.session.post(
            f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/",
            headers=self.fo_headers,
            data={"action": "list", "details": "All", "cve_id": self.cve_id},
            verify=CERT_PATH,
        )
        r.raise_for_status()
        root = ET.fromstring(r.content)

        _defaults = {
            "title":    "Unknown Vulnerability",
            "severity": "N/A",
            "solution": "Please refer to the vendor advisory for remediation steps.",
        }

        info: dict = {
            "cve_id":        self.cve_id,
            "qids":          [],
            "title":         _defaults["title"],
            "severity":      _defaults["severity"],
            "diagnosis":     "",
            "solution":      _defaults["solution"],
            "software_list": [],   # [{"product": str, "vendor": str}]
        }

        for vuln in root.findall(".//VULN"):
            # QID
            qid = (vuln.findtext("QID") or "").strip()
            if qid:
                info["qids"].append(qid)

            # Text fields — populate on first non-empty value found
            for xml_tag, key in [
                ("TITLE",          "title"),
                ("SEVERITY_LEVEL", "severity"),
                ("DIAGNOSIS",      "diagnosis"),
                ("SOLUTION",       "solution"),
            ]:
                val = (vuln.findtext(xml_tag) or "").strip()
                if val and info[key] == _defaults.get(key, ""):
                    info[key] = val

            # Affected software list (deduplicated by product name)
            for sw in vuln.findall(".//SOFTWARE"):
                prod = (sw.findtext("PRODUCT") or "").strip()
                vend = (sw.findtext("VENDOR")  or "").strip()
                if prod and not any(s["product"] == prod for s in info["software_list"]):
                    info["software_list"].append({"product": prod, "vendor": vend})

        sev_label = _SEVERITY.get(info["severity"], info["severity"])
        log.info(
            f"  Title    : {info['title']}\n"
            f"  Severity : {sev_label} ({info['severity']}/5)\n"
            f"  QIDs     : {info['qids'] or '(none — CVE may not be in your KB subscription)'}\n"
            f"  Affected : {[s['product'] for s in info['software_list']] or '(see solution text)'}"
        )
        return info

    # ── Step 2 : GAV — find hosts with this CVE ───────────────────────────
    #
    #  GAV filter field : "vuln.vulnerability.cveId"  (CSAM / GAV v2)
    #  If this returns 0 results, also try field="vulnerability.cveId"
    #  Reference: Qualys Asset Management & Tagging API User Guide

    def _build_gav_xml(self, offset: int) -> bytes:
        """Build paginated GAV ServiceRequest XML body with CVE ID filter."""
        root    = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        crit    = ET.SubElement(filters, "Criteria")
        crit.set("field", "vuln.vulnerability.cveId")
        crit.set("operator", "EQUALS")
        crit.text = self.cve_id
        prefs     = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text    = str(PAGE_SIZE)
        return ET.tostring(root, encoding="utf-8")

    def fetch_hosts_from_gav(self) -> dict:
        """
        Paginate through GAV HostAsset results filtered by CVE ID.

        Returns
        -------
        {host_id: {id, hostname, ip, fqdn, os, netbios}}
        """
        url          = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset, page = 1, 1
        hosts        = {}

        log.info(f"[GAV] Searching for all hosts with {self.cve_id} …")
        while True:
            log.info(f"  Page {page} (offset {offset}) …")
            r = self.session.post(
                url,
                headers=self.qps_headers,
                auth=self.auth,
                data=self._build_gav_xml(offset),
                verify=CERT_PATH,
            )
            if r.status_code == 401:
                raise RuntimeError(
                    "401 Unauthorized — ensure 'API Access' and 'Asset Management' "
                    "roles are enabled under Administration > Users."
                )
            r.raise_for_status()

            root   = ET.fromstring(r.content)
            assets = root.findall(".//HostAsset")
            if not assets:
                break

            for asset in assets:
                tx  = lambda p: (asset.findtext(p) or "").strip()
                hid = tx("id")
                if not hid:
                    continue
                hosts[hid] = {
                    "id":       hid,
                    "hostname": tx("dnsHostName") or tx("fqdn") or tx("netbiosName") or tx("address"),
                    "ip":       tx("address"),
                    "fqdn":     tx("fqdn"),
                    "os":       tx("os") or tx("operatingSystem"),
                    "netbios":  tx("netbiosName"),
                }

            log.info(f"    {len(assets)} asset(s) on page | running total: {len(hosts)}")
            if root.findtext(".//hasMoreRecords") != "true":
                break
            offset += PAGE_SIZE
            page   += 1

        log.info(f"[GAV] Total hosts with {self.cve_id}: {len(hosts)}")
        return hosts

    # ── Step 3 : VM Detection enrichment ──────────────────────────────────

    def fetch_detections_for_hosts(self, host_ids: list, qids: list) -> dict:
        """
        Fetch VM scan RESULTS for each host filtered to the relevant QIDs.
        The RESULTS field contains the installed software version and
        other scanner-specific output (package name, port, protocol, etc.).

        Batches host IDs in groups of DET_BATCH to stay within API limits.

        Returns
        -------
        {host_id: [{"qid": str, "status": str, "results": str}]}
        """
        out = defaultdict(list)

        if not qids:
            log.warning(
                "[Detection] No QIDs found — detection enrichment skipped. "
                "Email software section will fall back to KnowledgeBase data."
            )
            return out

        log.info(
            f"[Detection] Fetching scan results for {len(host_ids)} host(s) "
            f"in batches of {DET_BATCH} …"
        )
        for i in range(0, len(host_ids), DET_BATCH):
            batch = host_ids[i : i + DET_BATCH]
            b_num = i // DET_BATCH + 1
            log.info(f"  Batch {b_num}: hosts {i+1}–{min(i+DET_BATCH, len(host_ids))}")
            try:
                r = self.session.post(
                    f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/",
                    headers=self.fo_headers,
                    data={
                        "action":       "list",
                        "ids":          ",".join(batch),
                        "qids":         ",".join(qids),
                        "show_results": "1",
                        "status":       "Active,New,Re-Opened",
                    },
                    verify=CERT_PATH,
                )
                r.raise_for_status()
                root = ET.fromstring(r.content)

                for host_el in root.findall(".//HOST"):
                    hid = (host_el.findtext("ID") or "").strip()
                    for det in host_el.findall(".//DETECTION"):
                        out[hid].append({
                            "qid":     (det.findtext("QID")     or "").strip(),
                            "status":  (det.findtext("STATUS")  or "").strip(),
                            "results": (det.findtext("RESULTS") or "").strip(),
                        })

            except Exception as exc:
                log.warning(f"  Batch {b_num} failed: {exc}")

        log.info(
            f"[Detection] {sum(len(v) for v in out.values())} detection record(s) "
            f"across {len(out)} host(s)."
        )
        return out

    # ── Step 4 : Build draft email ─────────────────────────────────────────

    @staticmethod
    def _get_installed_ver(text: str) -> str:
        """Extract the installed/detected software version from raw RESULTS text."""
        m = _RE_INSTALLED.search(text)
        return m.group(1) if m else ""

    @staticmethod
    def _get_fix_ver(text: str) -> str:
        """Extract the recommended fix/update version from RESULTS or SOLUTION text."""
        m = _RE_FIXED.search(text)
        return m.group(1) if m else ""

    def build_draft_email(
        self,
        host:       dict,
        vuln_info:  dict,
        detections: list,
    ) -> dict:
        """
        Compose a draft email for one host.

        The email body includes:
          • Host identifying details (hostname, IP, FQDN, OS)
          • Vulnerability summary (CVE ID, title, severity)
          • Software version table: installed version | recommended fix version
          • Raw scan output snippets (first 3 records, first 8 lines each)
          • Full remediation steps from the KnowledgeBase
          • Required action checklist

        Returns {"subject": str, "body": str}
        """
        hostname  = host["hostname"] or host["ip"] or host["id"]
        sev_label = _SEVERITY.get(vuln_info["severity"], vuln_info["severity"])
        now_str   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        # ── Parse installed / fix versions from detection RESULTS ─────────
        sw_rows: list = []   # [(installed_version, fix_version, raw_results)]
        fix_ver       = ""

        for det in detections:
            raw  = det.get("results", "")
            inst = self._get_installed_ver(raw)
            fix  = self._get_fix_ver(raw)
            if fix and not fix_ver:
                fix_ver = fix
            sw_rows.append((inst or "—", fix or "—", raw))

        # Fallback 1: KB software list when no scan results available
        if not sw_rows and vuln_info["software_list"]:
            for sw in vuln_info["software_list"]:
                label = f"{sw['vendor']} {sw['product']}".strip()
                sw_rows.append((label, "—", ""))

        # Fallback 2: try to extract fix version from KB SOLUTION text
        if not fix_ver:
            fix_ver = (
                self._get_fix_ver(vuln_info["solution"])
                or "See Remediation Steps section below"
            )

        # ── Software version table ─────────────────────────────────────────
        C1, C2 = 36, 32
        divider = "  " + "─" * (C1 + C2 + 16)
        sw_lines = [
            "",
            f"  {'Installed / Vulnerable Version':<{C1}}  {'Recommended Fix Version':<{C2}}  Status",
            divider,
        ]
        for inst, fix, _ in sw_rows:
            sw_lines.append(f"  {inst:<{C1}}  {fix:<{C2}}  ⚠ VULNERABLE")
        if not sw_rows:
            sw_lines.append("  (No software version data available from the last scan)")
        sw_lines.append(divider)
        sw_table = "\n".join(sw_lines)

        # ── Raw scan output snippets (max 3 detections, 8 lines each) ─────
        raw_parts = []
        for det in detections[:3]:
            raw = det.get("results", "")
            if raw:
                clipped = "\n".join(raw.splitlines()[:8])
                raw_parts.append(
                    f"  [QID {det['qid']} | Status: {det['status']}]\n"
                    + "\n".join(f"    {line}" for line in clipped.splitlines())
                )
        raw_block = ""
        if raw_parts:
            raw_block = (
                "\n\nRaw Scan Detection Output  (first 3 records shown)\n"
                + "  " + "─" * 60 + "\n"
                + "\n\n".join(raw_parts)
                + "\n"
            )

        # ── Compose body ───────────────────────────────────────────────────
        SEP  = "═" * 70
        DASH = "─" * 70

        body_lines = [
            f"TO      : [FILL IN RECIPIENT EMAIL ADDRESS]",
            f"SUBJECT : [ACTION REQUIRED] {self.cve_id} — {sev_label} Vulnerability on {hostname}",
            f"DATE    : {datetime.now().strftime('%Y-%m-%d')}",
            "",
            SEP,
            f"  [{sev_label.upper()}] VULNERABILITY NOTIFICATION — {self.cve_id}",
            SEP,
            "",
            "Dear IT / Asset Owner,",
            "",
            f"The Vulnerability Management team has identified a {sev_label}-severity",
            f"vulnerability ({self.cve_id}) on a host under your responsibility.",
            "Please review the details below and apply the recommended remediation",
            "at the earliest opportunity.",
            "",
            DASH,
            "HOST DETAILS",
            DASH,
            f"  Hostname   : {host['hostname']}",
            f"  IP Address : {host['ip']}",
            f"  FQDN       : {host['fqdn']}",
            f"  OS         : {host['os']}",
            f"  Asset ID   : {host['id']}",
            "",
            DASH,
            "VULNERABILITY DETAILS",
            DASH,
            f"  CVE ID     : {self.cve_id}",
            f"  Title      : {vuln_info['title']}",
            f"  Severity   : {sev_label} ({vuln_info['severity']}/5)",
            f"  QID(s)     : {', '.join(vuln_info['qids']) or 'N/A'}",
            "",
            DASH,
            "VULNERABLE SOFTWARE & RECOMMENDED FIX VERSION",
            DASH,
            sw_table,
            raw_block,
            DASH,
            "REMEDIATION STEPS",
            DASH,
            vuln_info["solution"],
            "",
            DASH,
            "REQUIRED ACTIONS",
            DASH,
            "  1. Apply the fix / upgrade to the recommended version listed above ASAP.",
            "  2. Reply to this email with the date and method of remediation.",
            "  3. A follow-up vulnerability scan will be run to confirm the patch.",
            "",
            "  If this is a false positive, or the host is already patched,",
            "  please reply with supporting evidence so the record can be updated.",
            "",
            f"  SLA for {sev_label} findings: [ADD YOUR SLA TIMELINE HERE]",
            "",
            DASH,
            "Regards,",
            "Security / Vulnerability Management Team",
            "[Organisation Name]",
            "",
            f"[Auto-generated from Qualys GAV on {now_str} | Do not reply to this message]",
            DASH,
        ]
        body = "\n".join(body_lines)

        return {
            "subject": f"[ACTION REQUIRED] {self.cve_id} — {sev_label} Vulnerability on {hostname}",
            "body":    body,
        }

    # ── Step 5 : Save draft emails ─────────────────────────────────────────

    def save_emails(self, emails_with_hosts: list) -> str:
        """
        Write one .txt draft email file per host into a timestamped folder.

        File naming : 0001_<hostname>.txt, 0002_<hostname>.txt, …

        Returns the absolute path of the output folder.
        """
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(
            OUTPUT_DIR,
            f"draft_emails_{self.cve_id.replace('-', '_')}_{ts}",
        )
        os.makedirs(folder, exist_ok=True)

        log.info(f"\n[Save] Writing {len(emails_with_hosts)} draft email(s) → {folder}/")
        for i, (email, host) in enumerate(emails_with_hosts, start=1):
            safe  = (
                (host["hostname"] or f"host_{i}")
                .replace(".", "_")
                .replace(" ", "_")[:50]
            )
            fname = os.path.join(folder, f"{i:04d}_{safe}.txt")
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(email["body"])
            log.info(f"  [{i:04d}] {host['hostname']:<48} → {os.path.basename(fname)}")

        abs_path = os.path.abspath(folder)
        print()
        print("=" * 62)
        print(f"  Done! {len(emails_with_hosts)} draft email(s) saved.")
        print(f"  Output : {abs_path}/")
        print("=" * 62)
        print("  Next steps:")
        print("  1. Open each .txt file in the output folder.")
        print("  2. Fill in the 'TO' line with the recipient's email address.")
        print("  3. Paste the body into your email client and send.")
        print("=" * 62)
        print()
        return abs_path

    # ── Orchestrator ───────────────────────────────────────────────────────

    def run(self):
        """
        Full pipeline:
            login → KB lookup → GAV hosts → detection enrichment
            → build emails → save drafts → logout
        """
        self.login()
        try:
            # 1. Fetch CVE metadata from the Qualys KnowledgeBase
            vuln_info = self.get_vulnerability_info()

            # 2. Find all affected hosts in GAV using the CVE filter
            gav_hosts = self.fetch_hosts_from_gav()
            if not gav_hosts:
                log.warning(
                    "No hosts returned from GAV for this CVE.\n"
                    "  • Verify that vulnerability scanning is active.\n"
                    "  • Confirm the CVE ID is correct.\n"
                    "  • Check GAV filter field — try 'vulnerability.cveId' "
                    "if 'vuln.vulnerability.cveId' returns nothing."
                )
                return

            # 3. Enrich with per-host detection results (installed version)
            detections_by_id = self.fetch_detections_for_hosts(
                list(gav_hosts.keys()), vuln_info["qids"]
            )

            # 4. Compose one draft email per host
            log.info(f"[Email] Composing {len(gav_hosts)} draft email(s) …")
            emails_with_hosts = []
            for hid, host in gav_hosts.items():
                dets  = detections_by_id.get(hid, [])
                email = self.build_draft_email(host, vuln_info, dets)
                emails_with_hosts.append((email, host))
                log.info(
                    f"  {host['hostname']:<48}  "
                    f"{len(dets)} detection record(s)"
                )

            # 5. Save all draft emails to disk
            self.save_emails(emails_with_hosts)

        finally:
            self.logout()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cve_id = prompt_cve_id()
    QualysCVEMailer(cve_id).run()
  
