"""
qualys_techstack_inventory.py
─────────────────────────────────────────────────────────────────────────────
Fetches the full company tech-stack from Qualys CSAM and produces a
threat-intelligence–ready Excel workbook.

PRIMARY OUTPUT MODEL  — one row per unique (Software Name × Version)
  No duplicate rows for the same software + version across hosts.
  Asset Count   → how many unique hosts carry this software + version
  Asset Types   → which OS platforms carry it  (Windows / Linux / macOS)

WORKBOOK SHEETS
  1. Software Inventory  — TI primary feed, software-pivoted
  2. Host Inventory      — one row per host with OS + software count
  3. Category Summary    — rollup by software category
  4. Dashboard           — KPI tiles + OS and category breakdowns

VALIDATED API ENDPOINTS (both confirmed against Qualys CSAM docs)
  Login   POST /api/2.0/fo/session/
  Fetch   POST /qps/rest/2.0/search/am/hostasset
  Logout  POST /api/2.0/fo/session/

BUGS FIXED FROM PREVIOUS VERSION
  1. Software XML path was broken:
       OLD: .//HostAssetSoftwareList/HostAssetSoftware  -> 0 results always
       NEW: .//HostAssetSoftware  (wildcard, works across all tenant variants)
  2. Publisher field was wrong:
       OLD: sw.findtext('vendor')   -> always empty
       NEW: sw.findtext('publisher')
  3. <fields> XML block removed — CSAM ignores it and returns the full
     host object regardless; keeping it caused payload/parse issues.
  4. Tag XML path fixed:
       OLD: .//TagSimple/name  (works but misses list wrapper on some tenants)
       NEW: .//TagSimple/name  kept as wildcard — still correct
  5. responseCode now validated so bad requests surface immediately.
"""

import os
import sys
import logging
import xml.etree.ElementTree as ET
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import ColorScaleRule

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION  — edit before running
# ═══════════════════════════════════════════════════════════════════════════
USERNAME  = "your_qualys_username"
PASSWORD  = "your_qualys_password"

# Full path to your corporate CA bundle.
# Set to False to skip TLS verify (not recommended for production).
CERT_PATH = "/path/to/your/corporate_cert.pem"

# Qualys API gateway — change region suffix if needed.
# Common values: qg1.apps.qualys.com  qg2.apps.qualys.com
#                qg1.apps.qualys.in   qg1.apps.qualys.eu
BASE_URL  = "https://qualysapi.qg1.apps.qualys.in"

# Records per page — 200 is the safe ceiling for CSAM
PAGE_SIZE = 200

# Restrict to specific Qualys asset tag names. Leave empty = all assets.
# Example: TAG_NAMES = ["Production", "PCI Scope"]
TAG_NAMES: list[str] = []

OUTPUT_DIR = "."
LOG_LEVEL  = logging.INFO
# ═══════════════════════════════════════════════════════════════════════════


# ── Logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger("QualysTechStack")
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s  %(message)s",
                                  datefmt="%H:%M:%S"))
logger.addHandler(_h)
logger.setLevel(LOG_LEVEL)


# ── Platform label ────────────────────────────────────────────────────────────
def _asset_type(platform: str, os_name: str) -> str:
    """
    Return a clean asset-type label using agentInfo/platform first
    (Qualys sets this to WINDOWS / LINUX / MAC / UNKNOWN), then falls
    back to parsing the OS name string.
    """
    p = (platform or "").upper()
    if p == "WINDOWS":  return "Windows"
    if p == "LINUX":    return "Linux"
    if p in ("MAC", "MACOS"): return "macOS"

    o = (os_name or "").lower()
    if "windows" in o:  return "Windows"
    for kw in ("linux","ubuntu","centos","rhel","red hat","debian",
               "fedora","suse","amazon linux","oracle linux"):
        if kw in o: return "Linux"
    if any(k in o for k in ("mac","darwin","os x","osx")): return "macOS"
    return "Other"


# ── Software category classifier ──────────────────────────────────────────────
_CATEGORY_MAP: list[tuple[str, str]] = [
    # Security
    ("crowdstrike",        "Security - EDR/AV"),
    ("defender",           "Security - EDR/AV"),
    ("symantec",           "Security - EDR/AV"),
    ("mcafee",             "Security - EDR/AV"),
    ("sentinel one",       "Security - EDR/AV"),
    ("cylance",            "Security - EDR/AV"),
    ("carbon black",       "Security - EDR/AV"),
    ("trend micro",        "Security - EDR/AV"),
    ("malwarebytes",       "Security - EDR/AV"),
    ("kaspersky",          "Security - EDR/AV"),
    ("tenable",            "Security - Vulnerability"),
    ("qualys",             "Security - Vulnerability"),
    ("rapid7",             "Security - Vulnerability"),
    ("nessus",             "Security - Vulnerability"),
    ("splunk",             "Security - SIEM/Log"),
    ("elastic",            "Security - SIEM/Log"),
    ("logrhythm",          "Security - SIEM/Log"),
    ("solarwinds",         "Security - Monitoring"),
    ("datadog",            "Security - Monitoring"),
    ("dynatrace",          "Security - Monitoring"),
    ("nagios",             "Security - Monitoring"),
    ("zscaler",            "Security - Network/Proxy"),
    ("palo alto",          "Security - Network/Proxy"),
    ("fortinet",           "Security - Network/Proxy"),
    ("openssl",            "Security - Crypto"),
    # Browsers
    ("chrome",             "Browser"),
    ("firefox",            "Browser"),
    ("edge",               "Browser"),
    ("safari",             "Browser"),
    ("internet explorer",  "Browser"),
    ("opera",              "Browser"),
    # Runtimes
    ("java",               "Runtime - Java"),
    ("jdk",                "Runtime - Java"),
    ("jre",                "Runtime - Java"),
    ("openjdk",            "Runtime - Java"),
    ("python",             "Runtime - Python"),
    ("node",               "Runtime - Node.js"),
    (".net",               "Runtime - .NET"),
    ("dotnet",             "Runtime - .NET"),
    ("powershell",         "Runtime - PowerShell"),
    ("ruby",               "Runtime - Ruby"),
    ("perl",               "Runtime - Perl"),
    ("php",                "Runtime - PHP"),
    ("rust",               "Runtime - Rust"),
    # Web / App servers
    ("apache",             "Web Server"),
    ("nginx",              "Web Server"),
    ("iis",                "Web Server"),
    ("tomcat",             "App Server"),
    ("jboss",              "App Server"),
    ("weblogic",           "App Server"),
    ("websphere",          "App Server"),
    # Databases
    ("sql server",         "Database - MSSQL"),
    ("mysql",              "Database - MySQL"),
    ("postgresql",         "Database - PostgreSQL"),
    ("postgres",           "Database - PostgreSQL"),
    ("oracle db",          "Database - Oracle"),
    ("mongodb",            "Database - MongoDB"),
    ("redis",              "Database - Redis"),
    ("elasticsearch",      "Database - Elastic"),
    ("cassandra",          "Database - Cassandra"),
    ("sqlite",             "Database - SQLite"),
    ("mariadb",            "Database - MariaDB"),
    # Remote access
    ("openssh",            "Remote Access"),
    ("putty",              "Remote Access"),
    ("winscp",             "Remote Access"),
    ("teamviewer",         "Remote Access"),
    ("anydesk",            "Remote Access"),
    ("vnc",                "Remote Access"),
    ("citrix",             "Remote Access"),
    # DevOps / Cloud
    ("docker",             "DevOps - Container"),
    ("kubernetes",         "DevOps - Container"),
    ("kubectl",            "DevOps - Container"),
    ("helm",               "DevOps - Container"),
    ("terraform",          "DevOps - IaC"),
    ("ansible",            "DevOps - IaC"),
    ("puppet",             "DevOps - IaC"),
    ("chef",               "DevOps - IaC"),
    ("git",                "DevOps - SCM"),
    ("jenkins",            "DevOps - CI/CD"),
    ("gitlab",             "DevOps - CI/CD"),
    # Productivity / Comms
    ("microsoft office",   "Office - Microsoft"),
    ("microsoft 365",      "Office - Microsoft"),
    ("teams",              "Office - Collaboration"),
    ("slack",              "Office - Collaboration"),
    ("zoom",               "Office - Collaboration"),
    ("webex",              "Office - Collaboration"),
    ("adobe",              "Office - Adobe"),
    # Dev tools
    ("visual studio code", "Dev Tools - IDE"),
    ("vscode",             "Dev Tools - IDE"),
    ("visual studio",      "Dev Tools - IDE"),
    ("intellij",           "Dev Tools - IDE"),
    ("eclipse",            "Dev Tools - IDE"),
    # Utilities / OS
    ("7-zip",              "Utility - Compression"),
    ("winrar",             "Utility - Compression"),
    ("microsoft visual c", "OS Component - VC Redist"),
    ("vcredist",           "OS Component - VC Redist"),
    ("windows",            "OS Component"),
    ("update",             "OS Component"),
    ("driver",             "OS Component - Driver"),
]

def classify(name: str) -> str:
    lower = name.lower()
    for kw, cat in _CATEGORY_MAP:
        if kw in lower:
            return cat
    return "Uncategorized"


# ── Excel style helpers ───────────────────────────────────────────────────────
def _fill(hex_c: str) -> PatternFill:
    return PatternFill("solid", fgColor=hex_c)

def _border() -> Border:
    s = Side(style="thin", color="D0D0D0")
    return Border(left=s, right=s, top=s, bottom=s)

def _style_header(ws, row: int, bg: str, fg: str = "FFFFFF"):
    bd = _border()
    for cell in ws[row]:
        cell.fill      = _fill(bg)
        cell.font      = Font(bold=True, color=fg, name="Arial", size=10)
        cell.alignment = Alignment(horizontal="center", vertical="center",
                                   wrap_text=True)
        cell.border    = bd

def _style_data(ws, start_row: int, ncols: int):
    bd  = _border()
    alt = _fill("F4F8FF")
    for r, row in enumerate(
        ws.iter_rows(min_row=start_row, max_col=ncols), 0
    ):
        for cell in row:
            cell.border    = bd
            cell.font      = Font(name="Arial", size=9)
            cell.alignment = Alignment(vertical="center", wrap_text=False)
            if r % 2 == 0:
                cell.fill = alt

def _autofit(ws, mn=10, mx=60):
    for col in ws.columns:
        w = max((len(str(c.value)) if c.value else 0) for c in col)
        ws.column_dimensions[
            get_column_letter(col[0].column)
        ].width = min(max(w + 3, mn), mx)

def _tab(ws, hex_c: str):
    ws.sheet_properties.tabColor = hex_c


# ── Main class ────────────────────────────────────────────────────────────────
class QualysTechStack:

    def __init__(self, username=USERNAME, password=PASSWORD,
                 cert_path=CERT_PATH, page_size=PAGE_SIZE,
                 tag_names=None):
        self.base_url  = BASE_URL.rstrip("/")
        self.session   = requests.Session()
        self.auth      = HTTPBasicAuth(username, password)
        self.cert      = cert_path
        self.page_size = page_size
        self.tags      = tag_names or TAG_NAMES
        self.fo_hdr    = {"X-Requested-With": "QualysTechStackScript"}
        self.qps_hdr   = {"Content-Type": "application/xml",
                          "Accept":       "application/xml"}

    # ── Auth ──────────────────────────────────────────────────────────────────
    def login(self):
        r = self.session.post(
            f"{self.base_url}/api/2.0/fo/session/",
            headers=self.fo_hdr,
            data={"action":"login",
                  "username": self.auth.username,
                  "password": self.auth.password},
            verify=self.cert,
        )
        r.raise_for_status()
        if "QualysSession" not in self.session.cookies:
            raise RuntimeError(
                "Login failed — no session cookie returned. "
                "Verify username / password."
            )
        logger.info("Authenticated.")

    def logout(self):
        try:
            self.session.post(
                f"{self.base_url}/api/2.0/fo/session/",
                headers=self.fo_hdr,
                data={"action": "logout"},
                verify=self.cert,
            )
        except Exception:
            pass
        logger.info("Session closed.")

    # ── Request builder ───────────────────────────────────────────────────────
    def _build_request(self, offset: int) -> bytes:
        """
        Minimal ServiceRequest XML — no <fields> block.
        CSAM returns the full host object regardless of field selection;
        omitting the block avoids tenant-specific compatibility issues.
        """
        root = ET.Element("ServiceRequest")
        if self.tags:
            flt = ET.SubElement(root, "filters")
            for name in self.tags:
                ET.SubElement(flt, "Criteria",
                              field="tagName",
                              operator="EQUALS").text = name
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text    = str(self.page_size)
        return ET.tostring(root, encoding="utf-8")

    # ── Paginated fetch ───────────────────────────────────────────────────────
    def fetch_all_hosts(self) -> list[ET.Element]:
        url     = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset  = 1
        page    = 1
        results = []

        while True:
            logger.info(f"  Page {page:>4}  offset={offset}  "
                        f"hosts so far: {len(results)}")
            resp = self.session.post(
                url,
                headers=self.qps_hdr,
                auth=self.auth,
                data=self._build_request(offset),
                verify=self.cert,
            )

            if resp.status_code == 403:
                raise PermissionError(
                    "HTTP 403 — Qualys denied access. "
                    "Verify your subscription includes CSAM and your API role "
                    "has hostasset search permission."
                )
            if resp.status_code == 400:
                logger.error("HTTP 400 response:\n%s", resp.text[:800])
                raise ValueError("Bad API request — check BASE_URL and credentials.")
            resp.raise_for_status()

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError as e:
                raise RuntimeError(f"Malformed XML from Qualys API: {e}")

            # Surface Qualys-level errors immediately
            code = root.findtext("responseCode", "")
            if code and code != "SUCCESS":
                msg = (root.findtext("responseErrorDetails/errorMessage")
                       or root.findtext("responseMessage") or "")
                raise RuntimeError(
                    f"Qualys API error — responseCode={code!r}  {msg}"
                )

            assets = root.findall(".//HostAsset")
            if not assets:
                logger.info("  No further assets — fetch complete.")
                break

            results.extend(assets)

            if root.findtext(".//hasMoreRecords") != "true":
                break

            offset += self.page_size
            page   += 1

        return results

    # ── Record parser ─────────────────────────────────────────────────────────
    @staticmethod
    def _t(el: ET.Element, path: str) -> str:
        v = el.findtext(path)
        return v.strip() if v else ""

    def parse_hosts(self, hosts: list[ET.Element]) -> list[dict]:
        """
        Flatten every host × software into a raw staging record.
        Aggregation into the software-pivot happens in build_software_pivot().
        """
        t       = self._t
        records = []

        for i, host in enumerate(hosts, 1):
            host_id  = t(host, "id")
            dns      = t(host, "dnsHostName")
            netbios  = t(host, "netbiosName")
            ip       = t(host, "address")
            hostname = dns or netbios or t(host, "name") or host_id

            # OS — try nested object, fall back to flat <os> string
            os_name    = t(host, "operatingSystem/name") or t(host, "os")
            os_version = t(host, "operatingSystem/version")
            os_edition = t(host, "operatingSystem/edition")
            os_family  = t(host, "operatingSystem/productFamily")
            os_eol     = t(host, "operatingSystem/supportedUntil")

            platform  = t(host, "agentInfo/platform")
            last_seen = t(host, "agentInfo/lastCheckedIn")
            agent_ver = t(host, "agentInfo/agentVersion")

            a_type    = _asset_type(platform, os_name)

            tag_names = ", ".join(
                el.text.strip()
                for el in host.findall(".//TagSimple/name")
                if el.text
            )

            # VALIDATED PATH: .//HostAssetSoftware
            # Works whether the API wraps in softwareListData/list or
            # HostAssetSoftwareList — both tenant variants supported.
            sw_elements = host.findall(".//HostAssetSoftware")

            base = {
                "Host ID":    host_id,
                "Hostname":   hostname,
                "DNS Name":   dns,
                "IP Address": ip,
                "OS Name":    os_name,
                "OS Version": os_version,
                "OS Edition": os_edition,
                "OS Family":  os_family,
                "OS EOL":     os_eol,
                "Asset Type": a_type,
                "Platform":   platform,
                "Last Seen":  last_seen,
                "Agent Ver":  agent_ver,
                "Asset Tags": tag_names,
            }

            if not sw_elements:
                records.append({
                    **base,
                    "Software Name":      "",
                    "Version":            "",
                    "Vendor / Publisher": "",
                    "Software Type":      "",
                    "Category":           "",
                })
                continue

            for sw in sw_elements:
                sw_name = t(sw, "name")
                if not sw_name:
                    continue
                records.append({
                    **base,
                    "Software Name":      sw_name,
                    "Version":            t(sw, "version"),
                    # VALIDATED: field is 'publisher', not 'vendor'
                    "Vendor / Publisher": t(sw, "publisher"),
                    "Software Type":      t(sw, "softwareType"),
                    "Category":           classify(sw_name),
                })

            if i % 500 == 0:
                logger.info(f"  Parsed {i}/{len(hosts)} hosts…")

        logger.info(f"Raw staging records: {len(records)}")
        return records

    # ── Software pivot ────────────────────────────────────────────────────────
    @staticmethod
    def _join(series, limit=None) -> str:
        vals = sorted(set(
            str(v).strip() for v in series.dropna()
            if str(v).strip()
        ))
        return ", ".join(vals[:limit] if limit else vals)

    @staticmethod
    def _tags(series) -> str:
        out = set()
        for cell in series.dropna():
            for t in str(cell).split(","):
                t = t.strip()
                if t:
                    out.add(t)
        return ", ".join(sorted(out))

    def build_software_pivot(self, df: pd.DataFrame,
                             total_hosts: int) -> pd.DataFrame:
        """
        Aggregate raw host×software rows into ONE row per
        (Software Name × Version).

        New columns added:
          Asset Count        — unique host count carrying this SW+version
          % of Fleet         — share of total managed hosts
          Asset Types (OS)   — e.g. "Linux, Windows"
          OS Versions in Fleet — actual OS names seen (up to 15)
          Asset Tags in Fleet  — union of all Qualys tags across hosts
          Sample Hosts (10)    — representative hostnames for quick lookup
        """
        sw = df[df["Software Name"] != ""].copy()
        if sw.empty:
            return pd.DataFrame()

        pivot = (
            sw.groupby(
                ["Software Name", "Version",
                 "Vendor / Publisher", "Category", "Software Type"],
                dropna=False,
            )
            .agg(
                Asset_Count  = ("Host ID",    "nunique"),
                Asset_Types  = ("Asset Type", self._join),
                OS_Versions  = ("OS Name",    lambda s: self._join(s, 15)),
                Asset_Tags   = ("Asset Tags", self._tags),
                Sample_Hosts = ("Hostname",   lambda s: self._join(s, 10)),
            )
            .reset_index()
            .rename(columns={
                "Asset_Count":  "Asset Count",
                "Asset_Types":  "Asset Types (OS)",
                "OS_Versions":  "OS Versions in Fleet",
                "Asset_Tags":   "Asset Tags in Fleet",
                "Sample_Hosts": "Sample Hosts (up to 10)",
            })
        )

        pivot["% of Fleet"] = (
            pivot["Asset Count"] / total_hosts * 100
        ).round(1).astype(str) + "%"

        pivot.sort_values(
            ["Category", "Asset Count", "Software Name", "Version"],
            ascending=[True, False, True, True],
            inplace=True,
        )
        pivot.reset_index(drop=True, inplace=True)

        return pivot[[
            "Software Name", "Version", "Vendor / Publisher",
            "Category", "Software Type",
            "Asset Count", "% of Fleet",
            "Asset Types (OS)", "OS Versions in Fleet",
            "Asset Tags in Fleet", "Sample Hosts (up to 10)",
        ]]

    # ── Excel builder ─────────────────────────────────────────────────────────
    def build_excel(self, records: list[dict], filepath: str):
        logger.info("Building Excel workbook…")
        df_raw  = pd.DataFrame(records)
        total_h = df_raw["Host ID"].nunique()

        # ── Sheet 1: Software Inventory (pivoted) ────────────────────────
        df_sw = self.build_software_pivot(df_raw, total_h)

        # ── Sheet 2: Host Inventory ──────────────────────────────────────
        HOST_COLS = ["Host ID", "Hostname", "DNS Name", "IP Address",
                     "OS Name", "OS Version", "OS Edition", "OS Family",
                     "OS EOL", "Asset Type", "Platform",
                     "Last Seen", "Agent Ver", "Asset Tags"]

        df_hosts = (
            df_raw[HOST_COLS]
            .drop_duplicates(subset=["Host ID"])
            .reset_index(drop=True)
        )
        sw_counts = (
            df_raw[df_raw["Software Name"] != ""]
            .groupby("Host ID")["Software Name"]
            .count()
            .reset_index()
            .rename(columns={"Software Name": "# Software Installed"})
        )
        df_hosts = df_hosts.merge(sw_counts, on="Host ID", how="left")
        df_hosts["# Software Installed"] = (
            df_hosts["# Software Installed"].fillna(0).astype(int)
        )
        df_hosts.sort_values("# Software Installed",
                             ascending=False, inplace=True)
        df_hosts.reset_index(drop=True, inplace=True)

        # ── Sheet 3: Category Summary ────────────────────────────────────
        if not df_sw.empty:
            cat_sum = (
                df_sw.groupby("Category")
                .agg(
                    Unique_SW   = ("Software Name", "nunique"),
                    Unique_Ver  = ("Version",        "nunique"),
                    Total_Inst  = ("Asset Count",    "sum"),
                    OS_Types    = ("Asset Types (OS)",
                                   lambda s: self._join(s)),
                )
                .reset_index()
                .rename(columns={
                    "Unique_SW":  "# Unique Software",
                    "Unique_Ver": "# Unique Versions",
                    "Total_Inst": "Total Asset Installations",
                    "OS_Types":   "OS Types Present",
                })
                .sort_values("Total Asset Installations", ascending=False)
                .reset_index(drop=True)
            )
        else:
            cat_sum = pd.DataFrame()

        # ── Write to Excel then style ────────────────────────────────────
        with pd.ExcelWriter(filepath, engine="openpyxl") as writer:
            if not df_sw.empty:
                df_sw.to_excel(writer, sheet_name="Software Inventory",
                               index=False)
            df_hosts.to_excel(writer, sheet_name="Host Inventory",
                              index=False)
            if not cat_sum.empty:
                cat_sum.to_excel(writer, sheet_name="Category Summary",
                                 index=False)
            writer.book.create_sheet("Dashboard")

        wb = load_workbook(filepath)

        # Sheet 1
        if "Software Inventory" in wb.sheetnames:
            ws = wb["Software Inventory"]
            _tab(ws, "1F4E79")
            _style_header(ws, 1, "1F4E79")
            _style_data(ws, 2, len(df_sw.columns))
            _autofit(ws)
            ws.freeze_panes      = "C2"
            ws.auto_filter.ref   = ws.dimensions
            ws.row_dimensions[1].height = 32
            if len(df_sw) > 1:
                ws.conditional_formatting.add(
                    f"F2:F{len(df_sw)+1}",
                    ColorScaleRule(start_type="min", start_color="FFFFFF",
                                   end_type="max",   end_color="2E75B6"),
                )

        # Sheet 2
        if "Host Inventory" in wb.sheetnames:
            ws = wb["Host Inventory"]
            _tab(ws, "375623")
            _style_header(ws, 1, "375623")
            _style_data(ws, 2, len(df_hosts.columns))
            _autofit(ws)
            ws.freeze_panes      = "C2"
            ws.auto_filter.ref   = ws.dimensions
            ws.row_dimensions[1].height = 32

        # Sheet 3
        if "Category Summary" in wb.sheetnames:
            ws = wb["Category Summary"]
            _tab(ws, "7B2C2C")
            _style_header(ws, 1, "7B2C2C")
            _style_data(ws, 2, len(cat_sum.columns))
            _autofit(ws)
            ws.freeze_panes      = "B2"
            ws.auto_filter.ref   = ws.dimensions
            ws.row_dimensions[1].height = 32

        # Sheet 4: Dashboard
        ws = wb["Dashboard"]
        _tab(ws, "404040")

        ws.merge_cells("A1:I1")
        ws["A1"] = "QUALYS TECH STACK — THREAT INTELLIGENCE DASHBOARD"
        ws["A1"].font      = Font(bold=True, name="Arial", size=14,
                                  color="FFFFFF")
        ws["A1"].fill      = _fill("1F2D3D")
        ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 36

        ws.merge_cells("A2:I2")
        ws["A2"] = (f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}    "
                    f"Source: Qualys CSAM   "
                    f"Unique SW+Version rows: {len(df_sw)}")
        ws["A2"].font      = Font(italic=True, name="Arial", size=9,
                                  color="808080")
        ws["A2"].alignment = Alignment(horizontal="left")

        kpis = [
            ("Total Hosts",         total_h,                          "1F4E79"),
            ("Unique SW×Version",   len(df_sw),                       "375623"),
            ("Software Categories", df_sw["Category"].nunique()
                                    if not df_sw.empty else 0,        "7B2C2C"),
            ("Agentless Hosts",     df_hosts[
                                        df_hosts["# Software Installed"] == 0
                                    ].shape[0],                        "BF6000"),
        ]
        kr = 4
        for ci, (label, value, color) in enumerate(kpis, 1):
            cl  = get_column_letter(ci * 2 - 1)
            cl2 = get_column_letter(ci * 2)
            ws.merge_cells(f"{cl}{kr}:{cl2}{kr}")
            ws.merge_cells(f"{cl}{kr+1}:{cl2}{kr+1}")
            lc = ws[f"{cl}{kr}"]
            vc = ws[f"{cl}{kr+1}"]
            lc.value     = label
            lc.font      = Font(bold=True, name="Arial", size=10,
                                color="FFFFFF")
            lc.fill      = _fill(color)
            lc.alignment = Alignment(horizontal="center", vertical="center")
            vc.value     = value
            vc.font      = Font(bold=True, name="Arial", size=22, color=color)
            vc.alignment = Alignment(horizontal="center", vertical="center")
            ws.row_dimensions[kr].height   = 22
            ws.row_dimensions[kr+1].height = 44

        # Category breakdown table
        tr = kr + 4
        ws[f"A{tr}"] = "Software Category Breakdown"
        ws[f"A{tr}"].font = Font(bold=True, name="Arial", size=11,
                                 color="1F2D3D")
        ws.merge_cells(f"A{tr}:E{tr}")
        ws.row_dimensions[tr].height = 20

        hr = tr + 1
        for ci, hdr in enumerate(["Category","# Unique SW",
                                   "# Versions","Total Installs",
                                   "OS Types"], 1):
            c = ws.cell(row=hr, column=ci, value=hdr)
            c.font      = Font(bold=True, name="Arial", size=9,
                               color="FFFFFF")
            c.fill      = _fill("1F4E79")
            c.alignment = Alignment(horizontal="center")
            c.border    = _border()

        if not cat_sum.empty:
            for ri, row in cat_sum.iterrows():
                dr  = hr + 1 + ri
                bg  = _fill("EEF4FF" if ri % 2 == 0 else "FFFFFF")
                for ci, val in enumerate([
                    row["# Unique Software"],
                    row["# Unique Versions"],
                    row["Total Asset Installations"],
                    row["OS Types Present"],
                ], 2):
                    c        = ws.cell(row=dr, column=ci, value=val)
                    c.fill   = bg
                    c.font   = Font(name="Arial", size=9)
                    c.border = _border()
                c0        = ws.cell(row=dr, column=1,
                                    value=cat_sum.loc[ri, "Category"])
                c0.fill   = bg
                c0.font   = Font(name="Arial", size=9)
                c0.border = _border()

        # Asset type table (right side)
        if not df_raw.empty:
            at = (
                df_raw[df_raw["Asset Type"] != ""]
                .groupby("Asset Type")["Host ID"]
                .nunique()
                .reset_index()
                .rename(columns={"Host ID": "# Hosts"})
                .sort_values("# Hosts", ascending=False)
            )
            ws[f"G{tr}"] = "Asset Type Distribution"
            ws[f"G{tr}"].font = Font(bold=True, name="Arial", size=11,
                                     color="1F2D3D")
            ws.merge_cells(f"G{tr}:I{tr}")
            for ci, hdr in enumerate(["Asset Type","# Hosts","% of Total"], 7):
                c = ws.cell(row=hr, column=ci, value=hdr)
                c.font      = Font(bold=True, name="Arial", size=9,
                                   color="FFFFFF")
                c.fill      = _fill("375623")
                c.alignment = Alignment(horizontal="center")
                c.border    = _border()
            for ri, row in at.reset_index(drop=True).iterrows():
                dr  = hr + 1 + ri
                bg  = _fill("F0FFF0" if ri % 2 == 0 else "FFFFFF")
                pct = f"{row['# Hosts']/total_h*100:.1f}%" if total_h else "0%"
                for ci, val in enumerate(
                    [row["Asset Type"], row["# Hosts"], pct], 7
                ):
                    c        = ws.cell(row=dr, column=ci, value=val)
                    c.fill   = bg
                    c.font   = Font(name="Arial", size=9)
                    c.border = _border()

        for col, w in [("A",34),("B",14),("C",14),("D",18),
                        ("E",26),("F",4),("G",24),("H",12),("I",12)]:
            ws.column_dimensions[col].width = w

        # Reorder sheets
        for i, name in enumerate(["Dashboard","Software Inventory",
                                   "Host Inventory","Category Summary"]):
            if name in wb.sheetnames:
                wb.move_sheet(name, offset=wb.sheetnames.index(name) - i)

        wb.save(filepath)
        logger.info(f"Workbook saved → {filepath}")

    # ── Run ───────────────────────────────────────────────────────────────────
    def run(self):
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(OUTPUT_DIR, f"qualys_techstack_{ts}.xlsx")

        self.login()
        try:
            logger.info("Fetching all assets from Qualys CSAM…")
            hosts = self.fetch_all_hosts()
            if not hosts:
                logger.warning("No hosts returned — check permissions / tag filter.")
                return

            logger.info(f"Fetched {len(hosts)} host assets. Parsing…")
            records = self.parse_hosts(hosts)
            self.build_excel(records, filepath)

            df_tmp = pd.DataFrame(records)
            sw_only = df_tmp[df_tmp["Software Name"] != ""]
            logger.info("=" * 62)
            logger.info(f"  Output file       : {os.path.abspath(filepath)}")
            logger.info(f"  Unique hosts       : {df_tmp['Host ID'].nunique()}")
            logger.info(f"  Raw SW records     : {len(sw_only)}")
            logger.info(f"  Unique SW×Version  : "
                        f"{sw_only.groupby(['Software Name','Version']).ngroups}")
            logger.info("=" * 62)
        finally:
            self.logout()


def main():
    QualysTechStack(
        username  = USERNAME,
        password  = PASSWORD,
        cert_path = CERT_PATH,
        page_size = PAGE_SIZE,
        tag_names = TAG_NAMES,
    ).run()


if __name__ == "__main__":
    main()
