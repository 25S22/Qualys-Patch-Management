#!/usr/bin/env python3
"""
qualys_cve_emailer_outlook.py
─────────────────────────────────────────────────────────────────
Prompts for a CVE ID and software details, queries Qualys GAV for 
all affected hosts, and creates one ready-to-send draft email 
per host directly in your local Outlook Drafts folder.

* STRICT GAV VERSION: Operates using only the Asset Management / GAV API.
* OUTLOOK DRAFTS ONLY: Uses pywin32 to save drafts. DOES NOT SEND.
"""

import os
import sys
import logging
import urllib3
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
# ============================================================

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("QualysCVEMailer")

# Suppress InsecureRequestWarning if SSL verification is disabled
if not CERT_PATH:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def prompt_for_details() -> dict:
    """Prompts for CVE and standard software details to inject into drafts."""
    print("\n" + "=" * 62)
    print("  Qualys GAV Outlook Draft Generator")
    print("=" * 62)
    
    # CVE Validation
    while True:
        cve_id = input("\n  Enter CVE ID (e.g. CVE-2024-12345) : ").strip().upper()
        parts = cve_id.split("-")
        if (len(parts) >= 3 and parts[0] == "CVE" and parts[1].isdigit() and parts[2].isdigit()):
            print(f"  ✓  CVE ID accepted : {cve_id}")
            break
        print("  ✗  Invalid format. Expected CVE-YEAR-NUMBER.")

    print("\n  [Email Body Details]")
    software = input("  Software Name (e.g., Google Chrome)   : ").strip()
    inst_ver = input("  Installed/Vulnerable Version          : ").strip()
    upd_ver  = input("  Updated/Patched Target Version        : ").strip()

    return {
        "cve_id": cve_id,
        "software": software or "Unknown Software",
        "installed_version": inst_ver or "Detected by Qualys Scanner",
        "updated_version": upd_ver or "Refer to Vendor Advisory",
    }


class QualysCVEMailer:

    def __init__(self, details: dict):
        self.cve_id      = details["cve_id"]
        self.software    = details["software"]
        self.inst_ver    = details["installed_version"]
        self.upd_ver     = details["updated_version"]
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

    # ── GAV Search ────────────────────────────────────────────────────────

    def _build_gav_xml(self, offset: int) -> bytes:
        """Build paginated GAV ServiceRequest XML body with standard CVE filter."""
        root    = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        crit    = ET.SubElement(filters, "Criteria")
        crit.set("field", "vulnerability.cveId")
        crit.set("operator", "EQUALS")
        crit.text = self.cve_id
        
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text    = str(PAGE_SIZE)
        return ET.tostring(root, encoding="utf-8")

    def fetch_hosts_from_gav(self) -> dict:
        """Paginate through GAV HostAsset results filtered by CVE ID."""
        url          = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset, page = 1, 1
        hosts        = {}

        log.info(f"[GAV] Searching for all hosts vulnerable to {self.cve_id} …")
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
                    "401 Unauthorized — ensure API Access and Asset Management roles are enabled."
                )
            r.raise_for_status()

            root   = ET.fromstring(r.content)
            assets = root.findall(".//HostAsset")
            if not assets:
                break

            # Helper function for safe XML text extraction (fixes PEP 8 E731 lambda assignment)
            def _get_text(element: ET.Element, tag: str) -> str:
                val = element.findtext(tag)
                return val.strip() if val else ""

            for asset in assets:
                hid = _get_text(asset, "id")
                if not hid:
                    continue
                hosts[hid] = {
                    "id":       hid,
                    "hostname": _get_text(asset, "dnsHostName") or _get_text(asset, "fqdn") or _get_text(asset, "netbiosName") or _get_text(asset, "address"),
                    "ip":       _get_text(asset, "address"),
                    "fqdn":     _get_text(asset, "fqdn"),
                    "os":       _get_text(asset, "os") or _get_text(asset, "operatingSystem"),
                }

            if root.findtext(".//hasMoreRecords") != "true":
                break
            offset += PAGE_SIZE
            page   += 1

        log.info(f"[GAV] Total hosts found with {self.cve_id}: {len(hosts)}")
        return hosts

    # ── HTML Draft Email Generator ────────────────────────────────────────

    def build_draft_email(self, host: dict) -> dict:
        """Compose an HTML-formatted draft email for one host."""
        hostname = host["hostname"] or host["ip"] or host["id"]
        # Updated to use timezone-aware datetime
        now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        subject = f"[ACTION REQUIRED] Vulnerability {self.cve_id} detected on {hostname}"
        
        # HTML template for Outlook
        html_body = f"""
        <html>
        <body style="font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #333333;">
            <p>Dear IT / Asset Owner,</p>
            
            <p>The SOC Analysis & Automation team has identified a vulnerability (<strong>{self.cve_id}</strong>) 
            on a host under your responsibility during a recent Qualys scan. Please review the details below 
            and apply the recommended vendor patch at the earliest opportunity.</p>
            
            <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">HOST DETAILS</h3>
            <ul>
                <li><strong>Hostname:</strong> {host['hostname']}</li>
                <li><strong>IP Address:</strong> {host['ip']}</li>
                <li><strong>FQDN:</strong> {host['fqdn']}</li>
                <li><strong>OS:</strong> {host['os']}</li>
                <li><strong>Asset ID:</strong> {host['id']}</li>
            </ul>

            <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">VULNERABLE SOFTWARE DETAILS</h3>
            <p><strong>CVE ID:</strong> {self.cve_id}</p>
            
            <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; text-align: left; width: 100%; max-width: 600px; font-size: 11pt;">
                <tr style="background-color: #f2f2f2;">
                    <th>Software Name</th>
                    <th>Installed Version</th>
                    <th>Target Version</th>
                </tr>
                <tr>
                    <td>{self.software}</td>
                    <td style="color: #D32F2F; font-weight: bold;">{self.inst_ver}</td>
                    <td style="color: #388E3C; font-weight: bold;">{self.upd_ver}</td>
                </tr>
            </table>

            <h3 style="color: #005A9C; border-bottom: 1px solid #cccccc; padding-bottom: 3px;">REQUIRED ACTIONS</h3>
            <ol>
                <li>Update <strong>{self.software}</strong> to <strong>{self.upd_ver}</strong> (or later) ASAP.</li>
                <li>Reply to this email confirming the date and method of remediation.</li>
            </ol>
            
            <p><em>If this is a false positive, or the host is already patched, please reply with supporting 
            evidence so the inventory can be updated.</em></p>
            
            <br>
            <p>Regards,<br>
            <strong>SOC Analysis & Automation Team</strong><br>
            CRISIL Ltd</p>
            
            <hr style="border: 0; border-top: 1px solid #eeeeee;">
            <p style="font-size: 8pt; color: #999999;">[Draft automatically generated via Qualys GAV on {now_str}]</p>
        </body>
        </html>
        """

        return {
            "subject": subject,
            "body":    html_body,
        }

    # ── Create Outlook Drafts ─────────────────────────────────────────────

    def create_outlook_drafts(self, emails_with_hosts: list):
        """Uses pywin32 to generate and save emails directly into Outlook Drafts."""
        log.info(f"\n[Outlook] Connecting to local Outlook application...")
        
        try:
            outlook = win32.Dispatch('outlook.application')
        except Exception as e:
            log.error(f"Failed to connect to Outlook COM object. Ensure Outlook is open. Error: {e}")
            return

        log.info(f"[Outlook] Creating {len(emails_with_hosts)} draft(s) in your 'Drafts' folder...")
        
        for i, (email, host) in enumerate(emails_with_hosts, start=1):
            try:
                mail = outlook.CreateItem(0)  # 0 represents an Outlook MailItem
                mail.To = ""  # Intentionally left blank for manual review
                mail.Subject = email["subject"]
                mail.HTMLBody = email["body"]
                mail.Save()  # Saves to Drafts
                log.info(f"  [{i:04d}] Draft saved for {host['hostname']:<48}")
            except Exception as e:
                log.error(f"  [{i:04d}] Failed to save draft for {host['hostname']}. Error: {e}")

        print("\n" + "=" * 62)
        print(f"  Done! {len(emails_with_hosts)} draft(s) have been saved to your Outlook Drafts folder.")
        print("=" * 62 + "\n")

    # ── Orchestrator ──────────────────────────────────────────────────────

    def run(self):
        self.login()
        try:
            gav_hosts = self.fetch_hosts_from_gav()
            if not gav_hosts:
                log.warning(
                    "No hosts returned from GAV for this CVE.\n"
                    "  • Verify that vulnerability scanning is active.\n"
                    "  • Confirm the CVE ID is correct."
                )
                return

            log.info(f"[Email] Generating templates for {len(gav_hosts)} host(s) …")
            emails_with_hosts = []
            for hid, host in gav_hosts.items():
                email = self.build_draft_email(host)
                emails_with_hosts.append((email, host))

            self.create_outlook_drafts(emails_with_hosts)

        finally:
            self.logout()


if __name__ == "__main__":
    user_details = prompt_for_details()
    QualysCVEMailer(user_details).run()
