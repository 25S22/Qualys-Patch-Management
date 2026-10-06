"""
qualys_cve_watchlist.py
=======================
Pulls the most widespread critical CVEs from Qualys VMDR, ranks them by the
number of assets they affect, and writes an Excel file that can be used as
context for building a Vulnerability Watchlist in Recorded Future.

HOW IT WORKS
────────────
 Step 1 — FETCH DETECTIONS
   Calls the Host List VM Detection API
   (GET /api/2.0/fo/asset/host/vm/detection/) filtered to the severities and
   statuses you configure (default: severity 4-5, Confirmed, New/Active/
   Re-Opened) and follows the pagination links until every host is read.
   Builds a map of  QID → {set of host IDs}.

 Step 2 — ENRICH
   Calls the Knowledge Base API
   (POST /api/2.0/fo/knowledge_base/vuln/) for every QID found and reads the
   CVE list, title, CVSS, threat-intelligence tags and publish date.

 Step 3 — RANK & FILTER
   A QID can map to several CVEs and a CVE can map to several QIDs, so asset
   counts are calculated per CVE as the UNIQUE set of hosts across all of its
   QIDs (a host is never counted twice for the same CVE).
     • Drops CVEs whose asset count is NOT greater than MIN_ASSET_COUNT
     • Sorts by asset count (desc) → max QDS → CVSS v3
     • Keeps the first TOP_N rows

 Step 4 — EXPORT
   Saves an Excel workbook with two sheets:
     "CVE Watchlist"  – the ranked CVEs
     "Run Info"       – the parameters and totals used for this run

   This script is READ-ONLY — it never changes anything in Qualys.

PERMISSIONS REQUIRED
────────────────────
  • API Access
  • VM / VMDR module with access to the assets you want counted
    (counts only reflect hosts your account's asset groups / tags can see)

DEPENDENCIES
────────────
  pip install requests pandas openpyxl
"""

import os
import sys
import time
import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

import requests
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ←  edit these before running
# ──────────────────────────────────────────────────────────────────────────────
# Credentials: environment variables win if set, otherwise the defaults below.
USERNAME     = os.getenv("QUALYS_USERNAME", "your_qualys_username")
PASSWORD     = os.getenv("QUALYS_PASSWORD", "your_qualys_password")

# Your Qualys API server URL  (e.g. https://qualysapi.qg1.apps.qualys.in)
# Find it: Qualys UI → Help → About → Security Operations Center
BASE_URL     = "https://qualysapi.qg1.apps.qualys.in"

# SSL certificate bundle.  Set to False only in a trusted test environment.
CERT_PATH    = "/path/to/your/corporate_cert.pem"

# ── What to report ───────────────────────────────────────────────────────────
TOP_N            = 100     # how many CVEs to keep (50 / 100 / whatever you like)
MIN_ASSET_COUNT  = 100     # only keep CVEs affecting MORE THAN this many hosts
                           #   (strictly greater-than; set 0 to disable)

# Qualys severity levels to include.  5 = Urgent, 4 = Critical, 3 = Serious
# Accepts a single level, a comma list, or a range:  "5"  |  "4,5"  |  "4-5"
SEVERITY_LEVELS  = "4-5"

# "confirmed" = only confirmed detections (recommended, fewer false positives)
# "potential" = only potential detections   |   "" = both
VULN_TYPE        = "confirmed"

# Detection status to count.  Fixed detections are excluded by default.
DETECTION_STATUS = "New,Active,Re-Opened"

# Pull Qualys Detection Score (QDS) too.  Harmless if your subscription
# doesn't have it — the column will just be empty.
SHOW_QDS         = True

# Optional extra filters passed straight to the detection API, e.g.
#   {"ips": "10.0.0.0/16"}
#   {"use_tags": 1, "tag_set_by": "name", "tag_set_include": "Production"}
# Strongly recommended on very large subscriptions to keep the pull quick.
EXTRA_DETECTION_PARAMS = {}

# ── Performance / reliability ────────────────────────────────────────────────
HOSTS_PER_PAGE   = 1000    # hosts returned per detection page (truncation_limit)
KB_BATCH_SIZE    = 100     # QIDs per Knowledge Base request
TIMEOUT          = 600     # seconds to wait for a single API response
MAX_RETRIES      = 5       # attempts per request on 409 / 429 / 5xx
RETRY_WAIT       = 15      # seconds to wait if Qualys doesn't send Retry-After

# ── Output ───────────────────────────────────────────────────────────────────
# A timestamp is inserted before the extension, e.g. qualys_cve_watchlist_20250101_120000.xlsx
OUTPUT_FILE      = "qualys_cve_watchlist.xlsx"
# ──────────────────────────────────────────────────────────────────────────────


# ── Logging (stdout only — clean terminal output) ─────────────────────────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(message)s",
)
log = logging.getLogger("qualys_cve_watchlist")

LINE  = "─" * 65
DLINE = "═" * 65


# ── Small helpers ─────────────────────────────────────────────────────────────
def _to_float(val):
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _max_none(a, b):
    """max() that ignores None."""
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


# ──────────────────────────────────────────────────────────────────────────────
class QualysCVEWatchlist:

    def __init__(self):
        self.base_url   = BASE_URL.rstrip("/")
        self.session    = requests.Session()
        self.fo_headers = {"X-Requested-With": "QualysCVEWatchlist"}

    # ── Session ──────────────────────────────────────────────────────────────
    def login(self):
        r = self.session.post(
            f"{self.base_url}/api/2.0/fo/session/",
            headers=self.fo_headers,
            data={"action": "login", "username": USERNAME, "password": PASSWORD},
            verify=CERT_PATH,
            timeout=60,
        )
        r.raise_for_status()
        if "QualysSession" not in self.session.cookies:
            raise RuntimeError(
                "Login failed — no session cookie returned.\n"
                "Check USERNAME, PASSWORD and BASE_URL."
            )
        log.info(f"  ✔  Logged in to {self.base_url}")

    def logout(self):
        try:
            self.session.post(
                f"{self.base_url}/api/2.0/fo/session/",
                headers=self.fo_headers,
                data={"action": "logout"},
                verify=CERT_PATH,
                timeout=60,
            )
        except Exception:
            pass
        log.info("  ✔  Logged out")

    # ── HTTP helpers ─────────────────────────────────────────────────────────
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Send a request with automatic retry on 409 / 429 / 5xx.
        Qualys uses 409 for concurrency / rate-limit responses and sends a
        Retry-After header — we honour it when present.
        """
        for attempt in range(1, MAX_RETRIES + 1):
            r = self.session.request(
                method,
                url,
                headers=self.fo_headers,
                verify=CERT_PATH,
                timeout=TIMEOUT,
                **kwargs,
            )
            if r.status_code in (409, 429) or r.status_code >= 500:
                try:
                    wait = int(r.headers.get("Retry-After", RETRY_WAIT))
                except ValueError:
                    wait = RETRY_WAIT
                log.info(
                    f"  ⚠  HTTP {r.status_code} — waiting {wait}s and retrying "
                    f"({attempt}/{MAX_RETRIES})…"
                )
                time.sleep(wait)
                continue
            if r.status_code == 401:
                raise RuntimeError(
                    "HTTP 401 — check that your account has API Access and "
                    "access to the VM module."
                )
            r.raise_for_status()
            return r
        raise RuntimeError(f"Request failed after {MAX_RETRIES} attempts: {url}")

    @staticmethod
    def _parse(r: requests.Response) -> ET.Element:
        """Parse XML and raise if Qualys returned a SIMPLE_RETURN error."""
        root = ET.fromstring(r.content)
        if root.tag == "SIMPLE_RETURN":
            code = root.findtext(".//CODE", default="").strip()
            text = root.findtext(".//TEXT", default="").strip()
            raise RuntimeError(f"Qualys API error {code}: {text}")
        return root

    # ── Step 1: detections → QID → hosts ─────────────────────────────────────
    def fetch_detections(self) -> tuple[dict, dict, int]:
        """
        Returns:
          qid_hosts : { "qid": {host_id, host_id, …} }
          qid_qds   : { "qid": highest QDS seen for that QID }
          host_count: number of distinct hosts with at least one matching detection
        """
        params = {
            "action":           "list",
            "severities":       SEVERITY_LEVELS,
            "status":           DETECTION_STATUS,
            "show_results":     0,          # skip scan output → much smaller payload
            "truncation_limit": HOSTS_PER_PAGE,
            "output_format":    "XML",
        }
        if VULN_TYPE:
            params["include_vuln_type"] = VULN_TYPE
        if SHOW_QDS:
            params["show_qds"] = 1
        params.update(EXTRA_DETECTION_PARAMS)

        url        = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"
        qid_hosts  = defaultdict(set)
        qid_qds    = {}
        hosts_seen = set()
        page       = 0

        while url:
            page += 1
            r    = self._request("GET", url, params=params if page == 1 else None)
            root = self._parse(r)

            page_hosts = 0
            for host in root.iter("HOST"):
                hid = host.findtext("ID", default="").strip()
                if not hid:
                    continue
                page_hosts += 1
                hosts_seen.add(hid)
                for det in host.findall("./DETECTION_LIST/DETECTION"):
                    qid = det.findtext("QID", default="").strip()
                    if not qid:
                        continue
                    qid_hosts[qid].add(hid)
                    qds = _to_float(det.findtext("QDS"))
                    if qds is not None:
                        qid_qds[qid] = max(qid_qds.get(qid, 0), qds)

            log.info(
                f"  Page {page:<4} {page_hosts:>5} host(s)   "
                f"running total: {len(hosts_seen):,} host(s), "
                f"{len(qid_hosts):,} QID(s)"
            )

            # Qualys signals "more data" with a WARNING block holding the next URL
            next_url = root.findtext(".//WARNING/URL")
            url      = next_url.strip() if next_url else None
            time.sleep(0.3)   # polite gap

        return dict(qid_hosts), qid_qds, len(hosts_seen)

    # ── Step 2: Knowledge Base enrichment ────────────────────────────────────
    def fetch_kb(self, qids: list) -> dict:
        """
        Returns { "qid": {title, severity, cves[], cvss2, cvss3, intel[],
                          published, patchable} }
        """
        url   = f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/"
        qids  = sorted(qids, key=lambda q: int(q) if q.isdigit() else 0)
        total = len(qids)
        kb    = {}

        for start in range(0, total, KB_BATCH_SIZE):
            batch = qids[start: start + KB_BATCH_SIZE]
            end   = min(start + KB_BATCH_SIZE, total)
            log.info(f"  Knowledge Base [{start+1}–{end} of {total}]…")

            r    = self._request(
                "POST", url,
                data={"action": "list", "ids": ",".join(batch), "details": "All"},
            )
            root = self._parse(r)

            for v in root.findall(".//VULN_LIST/VULN"):
                qid = v.findtext("QID", default="").strip()
                if not qid:
                    continue
                cves = [
                    c.findtext("ID", default="").strip().upper()
                    for c in v.findall("./CVE_LIST/CVE")
                ]
                kb[qid] = {
                    "title":     v.findtext("TITLE", default="").strip(),
                    "severity":  int(v.findtext("SEVERITY_LEVEL", default="0") or 0),
                    "cves":      [c for c in cves if c.startswith("CVE-")],
                    "cvss2":     _to_float(v.findtext("./CVSS/BASE")),
                    "cvss3":     _to_float(v.findtext("./CVSS_V3/BASE")),
                    "intel":     [
                        t.text.strip()
                        for t in v.findall("./THREAT_INTELLIGENCE/THREAT_INTEL")
                        if t.text
                    ],
                    "published": (v.findtext("PUBLISHED_DATETIME", default="") or "")[:10],
                    "patchable": v.findtext("PATCHABLE", default="0").strip() == "1",
                }
            time.sleep(0.3)

        return kb

    # ── Step 3: aggregate by CVE, filter, rank ───────────────────────────────
    @staticmethod
    def build_cve_table(qid_hosts: dict, qid_qds: dict, kb: dict) -> tuple[dict, int]:
        """
        Collapse QID-level data into CVE-level data.
        Asset count = UNION of hosts across every QID that references the CVE.
        """
        cves        = {}
        no_cve_qids = 0

        for qid, hosts in qid_hosts.items():
            meta = kb.get(qid)
            if not meta or not meta["cves"]:
                no_cve_qids += 1      # misconfigs, info gathering, etc.
                continue

            for cve in meta["cves"]:
                e = cves.setdefault(cve, {
                    "hosts": set(), "qids": set(),
                    "title": "", "title_hosts": -1,
                    "severity": 0, "cvss2": None, "cvss3": None, "qds": None,
                    "intel": set(), "published": "", "patchable": False,
                })
                e["hosts"] |= hosts
                e["qids"].add(qid)

                # Use the title of the QID that touches the most hosts
                if len(hosts) > e["title_hosts"]:
                    e["title"], e["title_hosts"] = meta["title"], len(hosts)

                e["severity"]  = max(e["severity"], meta["severity"])
                e["cvss2"]     = _max_none(e["cvss2"], meta["cvss2"])
                e["cvss3"]     = _max_none(e["cvss3"], meta["cvss3"])
                e["qds"]       = _max_none(e["qds"], qid_qds.get(qid))
                e["intel"].update(meta["intel"])
                e["patchable"] = e["patchable"] or meta["patchable"]
                if meta["published"] and (not e["published"] or meta["published"] < e["published"]):
                    e["published"] = meta["published"]

        return cves, no_cve_qids

    @staticmethod
    def rank(cves: dict) -> tuple[pd.DataFrame, int]:
        """
        Apply MIN_ASSET_COUNT and TOP_N.
        Returns (dataframe, number_of_cves_above_threshold_before_TOP_N_cut).
        """
        rows = []
        for cve, e in cves.items():
            count = len(e["hosts"])
            if count <= MIN_ASSET_COUNT:
                continue
            intel_lc = [t.lower() for t in e["intel"]]
            rows.append({
                "CVE ID":               cve,
                "Affected Assets":      count,
                "QID Count":            len(e["qids"]),
                "QIDs":                 ", ".join(sorted(e["qids"], key=int)),
                "Title":                e["title"],
                "Qualys Severity":      e["severity"],
                "CVSS v3":              e["cvss3"],
                "CVSS v2":              e["cvss2"],
                "Max QDS":              e["qds"],
                "CISA KEV":             "Yes" if any("cisa" in t for t in intel_lc) else "No",
                "Active Attacks":       "Yes" if any("active_attacks" in t for t in intel_lc) else "No",
                "Threat Intel Tags":    ", ".join(sorted(e["intel"])),
                "Patchable":            "Yes" if e["patchable"] else "No",
                "Published (Qualys)":   e["published"],
            })

        above_threshold = len(rows)
        rows.sort(key=lambda x: (
            -x["Affected Assets"],
            -(x["Max QDS"] or 0),
            -(x["CVSS v3"] or 0),
            x["CVE ID"],
        ))
        rows = rows[:TOP_N]

        df = pd.DataFrame(rows)
        if not df.empty:
            df.insert(0, "Rank", range(1, len(df) + 1))
        return df, above_threshold

    # ── Step 4: Excel export ─────────────────────────────────────────────────
    @staticmethod
    def export(df: pd.DataFrame, info: list) -> str:
        ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base, ext   = os.path.splitext(OUTPUT_FILE)
        output_file = f"{base}_{ts}{ext or '.xlsx'}"

        info_df = pd.DataFrame(info, columns=["Parameter", "Value"])
        with pd.ExcelWriter(output_file, engine="openpyxl") as xw:
            df.to_excel(xw, sheet_name="CVE Watchlist", index=False)
            info_df.to_excel(xw, sheet_name="Run Info", index=False)

        _apply_styles(output_file)
        return output_file

    # ── Main flow ─────────────────────────────────────────────────────────────
    def run(self):
        log.info(DLINE)
        log.info("  Qualys Critical CVE Watchlist Builder")
        log.info(DLINE)
        log.info(f"  Severity levels     : {SEVERITY_LEVELS}")
        log.info(f"  Detection type      : {VULN_TYPE or 'confirmed + potential'}")
        log.info(f"  Detection status    : {DETECTION_STATUS}")
        log.info(f"  Top N               : {TOP_N}")
        log.info(f"  Min asset count     : > {MIN_ASSET_COUNT}")
        log.info(LINE)

        self.login()

        try:
            # ── STEP 1 — FETCH DETECTIONS ─────────────────────────────────────
            log.info("\n  STEP 1 — Fetching detections (this can take a while)…\n")
            qid_hosts, qid_qds, host_count = self.fetch_detections()

            if not qid_hosts:
                log.info("\n  No matching detections returned. Check the filters. Exiting.")
                return

            log.info(
                f"\n  ✔  {host_count:,} host(s) with {len(qid_hosts):,} "
                f"unique QID(s) matched your filters"
            )

            # ── STEP 2 — ENRICH ───────────────────────────────────────────────
            log.info("\n  STEP 2 — Enriching QIDs from the Knowledge Base…\n")
            kb = self.fetch_kb(list(qid_hosts.keys()))
            log.info(f"\n  ✔  {len(kb):,} / {len(qid_hosts):,} QID(s) resolved")

            # ── STEP 3 — RANK & FILTER ────────────────────────────────────────
            cves, no_cve_qids = self.build_cve_table(qid_hosts, qid_qds, kb)
            df, above         = self.rank(cves)

            log.info("")
            log.info(LINE)
            log.info("  RANKING RESULT")
            log.info(LINE)
            log.info(f"  Unique CVEs found                : {len(cves):,}")
            log.info(f"  QIDs without a CVE (skipped)     : {no_cve_qids:,}")
            log.info(f"  CVEs affecting > {MIN_ASSET_COUNT} host(s)   : {above:,}")
            log.info(f"  CVEs exported (Top {TOP_N})         : {len(df):,}")

            if df.empty:
                top_seen = max((len(e["hosts"]) for e in cves.values()), default=0)
                log.info(
                    f"\n  No CVE exceeded {MIN_ASSET_COUNT} affected host(s). "
                    f"Highest count seen: {top_seen}.\n"
                    f"  Lower MIN_ASSET_COUNT and re-run. No file written."
                )
                return

            log.info("")
            log.info(f"  {'#':<4} {'CVE ID':<16} {'Assets':>7}  {'CVSS3':>5}  {'KEV':<3}  Title")
            log.info(f"  {'─'*4} {'─'*16} {'─'*7}  {'─'*5}  {'─'*3}  {'─'*30}")
            for _, row in df.head(10).iterrows():
                cvss3 = f"{row['CVSS v3']:.1f}" if pd.notna(row["CVSS v3"]) else "  -"
                log.info(
                    f"  {row['Rank']:<4} {row['CVE ID']:<16} {row['Affected Assets']:>7}  "
                    f"{cvss3:>5}  {row['CISA KEV']:<3}  {str(row['Title'])[:45]}"
                )
            if len(df) > 10:
                log.info(f"  … and {len(df) - 10} more in the Excel file")

            # ── STEP 4 — EXPORT ───────────────────────────────────────────────
            info = [
                ("Generated (UTC)",                  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                ("Qualys platform",                  self.base_url),
                ("Severity levels",                  SEVERITY_LEVELS),
                ("Detection type",                   VULN_TYPE or "confirmed + potential"),
                ("Detection status",                 DETECTION_STATUS),
                ("Extra detection filters",          str(EXTRA_DETECTION_PARAMS) if EXTRA_DETECTION_PARAMS else "none"),
                ("TOP_N",                            TOP_N),
                ("MIN_ASSET_COUNT (strictly more than)", MIN_ASSET_COUNT),
                ("Hosts with matching detections",   host_count),
                ("Unique QIDs matched",              len(qid_hosts)),
                ("QIDs without a CVE (skipped)",     no_cve_qids),
                ("Unique CVEs found",                len(cves)),
                ("CVEs above asset threshold",       above),
                ("CVEs exported",                    len(df)),
            ]
            output_file = self.export(df, info)

            log.info("")
            log.info(DLINE)
            log.info("  COMPLETE")
            log.info(DLINE)
            log.info(f"  Results saved → {output_file}\n")

        finally:
            self.logout()


# ── Excel styling ─────────────────────────────────────────────────────────────
def _apply_styles(filepath: str):
    wb     = load_workbook(filepath)
    thin   = Side(style="thin", color="CCCCCC")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    for ws in wb.worksheets:
        # Header
        for cell in ws[1]:
            cell.fill      = PatternFill("solid", fgColor="1F4E79")
            cell.font      = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border    = border

        # Locate flag columns by header name (1-based)
        headers  = {c.value: c.column for c in ws[1]}
        kev_col  = headers.get("CISA KEV")
        atk_col  = headers.get("Active Attacks")

        for row_idx, row in enumerate(ws.iter_rows(min_row=2), start=2):
            alt_fill = PatternFill("solid", fgColor="EBF3FB") if row_idx % 2 == 0 else None
            for cell in row:
                cell.font      = Font(name="Calibri", size=10)
                cell.border    = border
                cell.alignment = Alignment(horizontal="left", vertical="center")
                if alt_fill:
                    cell.fill = alt_fill
            if kev_col and ws.cell(row=row_idx, column=kev_col).value == "Yes":
                ws.cell(row=row_idx, column=kev_col).fill = PatternFill("solid", fgColor="FFC7CE")  # red
            if atk_col and ws.cell(row=row_idx, column=atk_col).value == "Yes":
                ws.cell(row=row_idx, column=atk_col).fill = PatternFill("solid", fgColor="FFEB9C")  # amber

        # Auto column widths
        for col in ws.columns:
            letter    = get_column_letter(col[0].column)
            max_width = max(len(str(c.value)) if c.value is not None else 0 for c in col)
            ws.column_dimensions[letter].width = min(max_width + 4, 55)

        ws.freeze_panes    = "A2"
        ws.auto_filter.ref = ws.dimensions

    wb.save(filepath)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    QualysCVEWatchlist().run()
