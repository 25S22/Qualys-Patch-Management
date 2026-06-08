#!/usr/bin/env python3
"""
qualys_cve_emailer_outlook_auto.py
─────────────────────────────────────────────────────────────────
Prompts for a CVE ID, uses the KnowledgeBase to find associated QIDs, 
queries GAV for affected hosts, pulls exact software versions via 
the VM Detection API, and creates Outlook drafts via COM.
"""

import os
import re
import sys
import logging
import urllib3
from collections import defaultdict
from datetime import datetime, timezone

import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

try:
    import win32com.client as win32
except ImportError:
    print("Error: The 'pywin32' library is required to create Outlook drafts.")
    print("Please install it using: pip install pywin32")
    sys.exit(1)

# ============================================================
# CONFIGURATION
# ============================================================
USERNAME   = "your_qualys_username"
PASSWORD   = "your_qualys_password"
CERT_PATH  = False  # Path to cert or False to skip SSL verify
BASE_URL   = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE  = 100   # GAV results per paginated page
DET_BATCH  = 50    # Host IDs per VM Detection API batch call
# ============================================================

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("QualysCVEMailer")

if not CERT_PATH:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Regex to extract versions from raw Qualys scan RESULTS
_RE_INSTALLED = re.compile(r"(?:installed|detected|running|current)(?:\s+(?:version|package))?[\s:]*([\d][\w.\-]+)", re.IGNORECASE)
_RE_FIXED = re.compile(r"(?:fixed|updated|upgrade\s+to|update\s+to|patched\s+in)[\s:]*([\d][\w.\-]+)", re.IGNORECASE)


def prompt_cve_id() -> str:
    print("\n" + "=" * 62)
    print("  Qualys Automated Outlook Draft Generator")
    print("=" * 62)
    while True:
        raw = input("\n  Enter CVE ID (e.g. CVE-2024-12345) : ").strip().upper()
        parts = raw.split("-")
        if len(parts) >= 3 and parts[0] == "CVE" and parts[1].isdigit() and parts[2].isdigit():
            print(f"  ✓  CVE ID accepted : {raw}\n")
            return raw
        print("  ✗  Invalid format. Expected CVE-YEAR-NUMBER.")


class QualysCVEMailer:

    def __init__(self, cve_id: str):
        self.cve_id      = cve_id
        self.base_url    = BASE_URL.rstrip("/")
        self.session     = requests.Session()
        self.auth        = HTTPBasicAuth(USERNAME, PASSWORD)
        self.fo_headers  = {"X-Requested-With": "Python"}
        self.qps_headers = {"Content-Type": "application/xml", "Accept": "application/xml"}

    def login(self):
        r = self.session.post(f"{self.base_url}/api/2.0/fo/session/", headers=self.fo_headers,
                              data={"action": "login", "username": USERNAME, "password": PASSWORD}, verify=CERT_PATH)
        r.raise_for_status()
        log.info("Logged in successfully.")

    def logout(self):
        try:
            self.session.post(f"{self.base_url}/api/2.0/fo/session/", headers=self.fo_headers,
                              data={"action": "logout"}, verify=CERT_PATH)
        except Exception: pass

    # ── Step 1: KnowledgeBase (Get QIDs) ──────────────────────────────────

    def get_vulnerability_info(self) -> dict:
        log.info(f"[KB] Fetching QIDs and metadata for {self.cve_id}...")
        r = self.session.post(f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/", headers=self.fo_headers,
                              data={"action": "list", "details": "All", "cve_id": self.cve_id}, verify=CERT_PATH)
        r.raise_for_status()
        root = ET.fromstring(r.content)

        info = {"qids": [], "title": "Unknown Vulnerability", "software": "Detected Software"}
        for vuln in root.findall(".//VULN"):
            qid = (vuln.findtext("QID") or "").strip()
            if qid: info["qids"].append(qid)
            if vuln.findtext("TITLE"): info["title"] = vuln.findtext("TITLE").strip()
            
            # Try to grab a generic software name from KB if available
            sw = vuln.find(".//SOFTWARE")
            if sw is not None and sw.findtext("PRODUCT"):
                info["software"] = sw.findtext("PRODUCT").strip()

        log.info(f"  Found QIDs: {info['qids']}")
        return info

    # ── Step 2: GAV (Get Hosts) ───────────────────────────────────────────

    def fetch_hosts_from_gav(self) -> dict:
        url, offset, hosts = f"{self.base_url}/qps/rest/2.0/search/am/hostasset", 1, {}
        log.info(f"[GAV] Searching for hosts vulnerable to {self.cve_id}...")
        
        while True:
            root_xml = ET.Element("ServiceRequest")
            filters = ET.SubElement(root_xml, "filters")
            crit = ET.SubElement(filters, "Criteria")
            crit.set("field", "vulnerability.cveId")
            crit.set("operator", "EQUALS")
            crit.text = self.cve_id
            prefs = ET.SubElement(root_xml, "preferences")
            ET.SubElement(prefs, "startFromOffset").text = str(offset)
            ET.SubElement(prefs, "limitResults").text = str(PAGE_SIZE)

            r = self.session.post(url, headers=self.qps_headers, auth=self.auth, 
                                  data=ET.tostring(root_xml), verify=CERT_PATH)
            r.raise_for_status()
            root = ET.fromstring(r.content)
            assets = root.findall(".//HostAsset")
            if not assets: break

            for asset in assets:
                hid = (asset.findtext("id") or "").strip()
                if hid:
                    hosts[hid] = {
                        "id": hid,
                        "hostname": asset.findtext("dnsHostName") or asset.findtext("address") or "Unknown",
                        "ip": asset.findtext("address") or "Unknown",
                        "os": asset.findtext("os") or "Unknown",
                    }
            if root.findtext(".//hasMoreRecords") != "true": break
            offset += PAGE_SIZE

        log.info(f"  Total hosts found: {len(hosts)}")
        return hosts

    # ── Step 3: VM Detection (Get Exact Versions) ─────────────────────────

    def fetch_detections(self, host_ids: list, qids: list) -> dict:
        out = defaultdict(list)
        if not qids: return out
        
        log.info(f"[VM] Extracting exact software versions from scan results...")
        for i in range(0, len(host_ids), DET_BATCH):
            batch = host_ids[i : i + DET_BATCH]
            try:
                r = self.session.post(f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/", headers=self.fo_headers,
                                      data={"action": "list", "ids": ",".join(batch), "qids": ",".join(qids), "show_results": "1"}, 
                                      verify=CERT_PATH)
                root = ET.fromstring(r.content)
                for host_el in root.findall(".//HOST"):
                    hid = (host_el.findtext("ID") or "").strip()
                    for det in host_el.findall(".//DETECTION"):
                        out[hid].append((det.findtext("RESULTS") or "").strip())
            except Exception as e:
                log.warning(f"  Failed batch: {e}")
        return out

    # ── Step 4: Build & Save Outlook Drafts ───────────────────────────────

    def process_and_draft(self, hosts: dict, vuln_info: dict, detections: dict):
        log.info(f"\n[Outlook] Connecting to local Outlook application...")
        try:
            outlook = win32.Dispatch('outlook.application')
        except Exception as e:
            log.error(f"Failed to connect to Outlook. Error: {e}")
            return

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        for hid, host in hosts.items():
            # Parse scan results for versions
            raw_results = " ".join(detections.get(hid, []))
            
            m_inst = _RE_INSTALLED.search(raw_results)
            m_fix = _RE_FIXED.search(raw_results)
            
            inst_ver = m_inst.group(1) if m_inst else "Check Qualys Scan Report"
            upd_ver = m_fix.group(1) if m_fix else "Refer to Vendor Advisory"

            subject = f"[ACTION REQUIRED] Vulnerability {self.cve_id} detected on {host['hostname']}"
            html_body = f"""
            <html>
            <body style="font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #333333;">
                <p>Dear IT / Asset Owner,</p>
                <p>The SOC Analysis & Automation team has identified a vulnerability (<strong>{self.cve_id}</strong>) 
                on a host under your responsibility during a recent Qualys scan.</p>
                
                <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">HOST DETAILS</h3>
                <ul>
                    <li><strong>Hostname:</strong> {host['hostname']}</li>
                    <li><strong>IP Address:</strong> {host['ip']}</li>
                    <li><strong>OS:</strong> {host['os']}</li>
                </ul>

                <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">VULNERABLE SOFTWARE</h3>
                <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; text-align: left; width: 100%; max-width: 600px; font-size: 11pt;">
                    <tr style="background-color: #f2f2f2;">
                        <th>Software / Issue</th>
                        <th>Installed Version</th>
                        <th>Target Version</th>
                    </tr>
                    <tr>
                        <td>{vuln_info['software']}</td>
                        <td style="color: #D32F2F; font-weight: bold;">{inst_ver}</td>
                        <td style="color: #388E3C; font-weight: bold;">{upd_ver}</td>
                    </tr>
                </table>

                <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">REQUIRED ACTIONS</h3>
                <ol>
                    <li>Apply the recommended patch or upgrade to the target version ASAP.</li>
                    <li>Reply to this email confirming the date and method of remediation.</li>
                </ol>
                
                <br>
                <p>Regards,<br><strong>SOC Analysis & Automation Team</strong></p>
                <hr style="border: 0; border-top: 1px solid #eeeeee;">
                <p style="font-size: 8pt; color: #999999;">[Draft automatically generated on {now_str}]</p>
            </body>
            </html>
            """
            
            try:
                mail = outlook.CreateItem(0)
                mail.Subject = subject
                mail.HTMLBody = html_body
                mail.Save()
                log.info(f"  Draft saved for {host['hostname']}")
            except Exception as e:
                log.error(f"  Failed to save draft for {host['hostname']}: {e}")

        print("\n" + "=" * 62)
        print(f"  Done! Outlook drafts have been generated.")
        print("=" * 62 + "\n")

    def run(self):
        self.login()
        try:
            vuln_info = self.get_vulnerability_info()
            gav_hosts = self.fetch_hosts_from_gav()
            if not gav_hosts:
                log.warning("No hosts returned for this CVE.")
                return
                
            detections = self.fetch_detections(list(gav_hosts.keys()), vuln_info["qids"])
            self.process_and_draft(gav_hosts, vuln_info, detections)
        finally:
            self.logout()


if __name__ == "__main__":
    cve = prompt_cve_id()
    QualysCVEMailer(cve).run()
