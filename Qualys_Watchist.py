"""
qualys_cve_watchlist.py
=======================
Pulls the most widespread critical CVEs from Qualys VMDR, ranks them by the
number of assets they affect, and writes an Excel file that can be used as
context for building a Vulnerability Watchlist in Recorded Future.

APIs USED  (VMDR only — nothing else is called)
───────────────────────────────────────────────
  1. POST /api/2.0/fo/session/                  login / logout
  2. GET  /api/2.0/fo/asset/host/vm/detection/  Host List VM Detection
  3. POST /api/2.0/fo/knowledge_base/vuln/      VM Knowledge Base

  No other Qualys module or API is called. Asset counts come purely from
  VMDR host detections.

HOW IT WORKS
────────────
 Step 1 — FETCH DETECTIONS
   Reads host detections filtered by severity and status (default: severity
   4-5, New/Active/Re-Opened) and follows the pagination links until every
   host has been read.  Builds a map of  QID → {set of host IDs}.
   Potential detections are dropped client-side unless INCLUDE_POTENTIAL=True.

 Step 2 — ENRICH
   Looks up every QID in the Knowledge Base for its CVE list, title, CVSS,
   threat-intelligence tags and publish date.

 Step 3 — RANK & FILTER
   A QID can map to several CVEs and a CVE to several QIDs, so asset counts
   are calculated per CVE as the UNIQUE set of hosts across all of its QIDs.
     • Drops CVEs whose asset count is NOT greater than MIN_ASSET_COUNT
     • Sorts by asset count (desc) → CVSS v3 → Qualys severity
     • Keeps the first TOP_N rows

 Step 4 — EXPORT
   Saves an Excel workbook:
     "CVE Watchlist"  – the ranked CVEs
     "Run Info"       – the parameters and totals used for this run

   This script is READ-ONLY — it never changes anything in Qualys.

TROUBLESHOOTING
───────────────
  • Errors print Qualys's own message (HTTP status, code and text).
  • If your platform rejects an optional parameter ("Unrecognized
    parameter(s): …") the script drops it automatically and retries.
  • If nothing is found, the script runs an unfiltered test call and tells you
    whether the problem is your filters or your account's asset scope.
  • If CVEs exist but none beat MIN_ASSET_COUNT, the highest counts are shown
    so you can pick a sensible threshold.
  • Set DEBUG_SAVE_XML = True to keep the raw first-page XML for inspection.

PERMISSIONS REQUIRED
────────────────────
  • API Access
  • VMDR access to the assets you want counted (counts only reflect hosts your
    account's asset groups / tags can see)

DEPENDENCIES
────────────
  pip install requests pandas openpyxl
"""

import os
import re
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

# SSL certificate bundle.  Use a .pem path, True (system CAs), or False for a
# trusted test environment only.
CERT_PATH    = "/path/to/your/corporate_cert.pem"

# ── What to report ───────────────────────────────────────────────────────────
TOP_N            = 100     # how many CVEs to keep (50 / 100 / whatever you like)
MIN_ASSET_COUNT  = 100     # only keep CVEs affecting MORE THAN this many hosts
                           #   (strictly greater-than; set 0 to disable)

# Qualys severity levels to include.  5 = Urgent, 4 = Critical, 3 = Serious
# Accepts a single level, a comma list, or a range:  "5"  |  "4,5"  |  "4-5"
SEVERITY_LEVELS  = "4-5"

# Detection status to count.  Fixed detections are excluded by default.
DETECTION_STATUS = "New,Active,Re-Opened"

# False = count only CONFIRMED detections (recommended, fewer false positives)
# True  = also count POTENTIAL detections
INCLUDE_POTENTIAL = False

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

# True = save raw first-page XML files (qualys_debug_*.xml) for inspection
DEBUG_SAVE_XML   = False

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
class QualysAPIError(RuntimeError):
    """Raised for any Qualys error, carrying the real message."""

    def __init__(self, status, code, text):
        self.status, self.code, self.text = status, code, text
        super().__init__(f"Qualys API error — HTTP {status}"
                         f"{' | code ' + code if code else ''}: {text}")


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


def _debug_save(name: str, content: bytes):
    if DEBUG_SAVE_XML:
        path = f"qualys_debug_{name}.xml"
        with open(path, "wb") as fh:
            fh.write(content)
        log.info(f"  [debug] raw response saved → {path}")


# ──────────────────────────────────────────────────────────────────────────────
class QualysCVEWatchlist:

    def __init__(self):
        self.base_url   = BASE_URL.rstrip("/")
        self.session    = requests.Session()
        self.fo_headers = {"X-Requested-With": "QualysCVEWatchlist"}
        self.det_url    = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"

    # ── Config sanity check ──────────────────────────────────────────────────
    @staticmethod
    def _check_config():
        problems = []
        if USERNAME.startswith("your_") or PASSWORD.startswith("your_"):
            problems.append(
                "USERNAME / PASSWORD still hold placeholder values "
                "(edit them, or set QUALYS_USERNAME / QUALYS_PASSWORD)."
            )
        if isinstance(CERT_PATH, str) and not os.path.isfile(CERT_PATH):
            problems.append(
                f"CERT_PATH file not found: {CERT_PATH}  "
                "(use a real .pem path, True, or False for testing)."
            )
        if not BASE_URL.startswith("https://"):
            problems.append("BASE_URL must start with https://")
        if problems:
            raise ValueError("Configuration problem(s):\n    - " + "\n    - ".join(problems))

    # ── Session ──────────────────────────────────────────────────────────────
    def login(self):
        self._request(
            "POST", f"{self.base_url}/api/2.0/fo/session/",
            data={"action": "login", "username": USERNAME, "password": PASSWORD},
        )
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
    @staticmethod
    def _api_error(r: requests.Response) -> QualysAPIError:
        """Build an error that includes whatever Qualys said."""
        code = text = ""
        try:
            root = ET.fromstring(r.content)
            code = root.findtext(".//CODE", default="").strip()
            text = root.findtext(".//TEXT", default="").strip()
        except ET.ParseError:
            pass
        if not text:
            text = (r.text or "").strip()[:500] or "(empty response body)"
        if r.status_code == 401:
            text += "  → check credentials; the account needs API Access."
        elif r.status_code == 403:
            text += "  → permission denied; check API Access, role and asset-group scope."
        elif r.status_code in (409, 429):
            text += "  → concurrency / rate limit; wait a few minutes and re-run."
        return QualysAPIError(r.status_code, code, text)

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
            retryable = r.status_code in (409, 429) or r.status_code >= 500
            if retryable and attempt < MAX_RETRIES:
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
            if r.status_code >= 400:
                raise self._api_error(r)
            return r
        raise RuntimeError("unreachable")   # pragma: no cover

    @staticmethod
    def _parse(r: requests.Response) -> ET.Element:
        """Parse XML and raise if Qualys returned a SIMPLE_RETURN error."""
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError:
            snippet = (r.text or "")[:300].replace("\n", " ")
            raise RuntimeError(f"Qualys returned a non-XML response: {snippet}")
        if root.tag == "SIMPLE_RETURN":
            code = root.findtext(".//CODE", default="").strip()
            text = root.findtext(".//TEXT", default="").strip()
            raise QualysAPIError(r.status_code, code, text)
        return root

    @staticmethod
    def _unrecognized_params(text: str) -> list:
        """Pull parameter names out of 'Unrecognized parameter(s): a, b (…)'."""
        m = re.search(r"Unrecognized parameter\(s\):\s*([^()]+)", text or "", re.I)
        return [p.strip() for p in m.group(1).split(",") if p.strip()] if m else []

    # ── Step 1: detections → QID → hosts ─────────────────────────────────────
    def fetch_detections(self) -> tuple[dict, int, int]:
        """
        Returns:
          qid_hosts        : { "qid": {host_id, host_id, …} }
          hosts_returned   : number of hosts Qualys sent back (before client filters)
          skipped_potential: detections dropped because INCLUDE_POTENTIAL is False
        """
        params = {
            "action":           "list",
            "severities":       SEVERITY_LEVELS,
            "status":           DETECTION_STATUS,
            "show_results":     0,          # skip scan output → much smaller payload
            "truncation_limit": HOSTS_PER_PAGE,
            "output_format":    "XML",
        }
        params.update(EXTRA_DETECTION_PARAMS)

        url               = self.det_url
        qid_hosts         = defaultdict(set)
        hosts_seen        = set()
        skipped_potential = 0
        page              = 0

        while url:
            page += 1
            try:
                r    = self._request("GET", url, params=params if page == 1 else None)
                root = self._parse(r)
            except QualysAPIError as e:
                # Platform rejected an optional parameter → drop it and retry
                bad = [p for p in self._unrecognized_params(e.text)
                       if p in params and p != "action"]
                if page == 1 and bad:
                    for p in bad:
                        params.pop(p)
                    log.info(f"  ⚠  Platform rejected parameter(s) {bad} — "
                             f"dropped, retrying…")
                    page = 0
                    continue
                raise

            if page == 1:
                _debug_save("detection_page1", r.content)

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
                    dtype = det.findtext("TYPE", default="").strip().lower()
                    if dtype == "info":
                        continue
                    if dtype == "potential" and not INCLUDE_POTENTIAL:
                        skipped_potential += 1
                        continue
                    qid_hosts[qid].add(hid)

            log.info(
                f"  Page {page:<4} {page_hosts:>5} host(s)   "
                f"running total: {len(hosts_seen):,} host(s), "
                f"{len(qid_hosts):,} QID(s)"
            )

            # Qualys signals "more data" with a WARNING block holding the next URL
            next_url = root.findtext(".//WARNING/URL")
            url      = next_url.strip() if next_url else None
            time.sleep(0.3)   # polite gap

        return dict(qid_hosts), len(hosts_seen), skipped_potential

    def diagnose_empty(self):
        """Unfiltered test call — tells the user WHY nothing came back."""
        log.info("\n  Running a diagnostic call with NO severity/status filters…")
        try:
            r     = self._request("GET", self.det_url, params={
                "action": "list", "truncation_limit": 5, "show_results": 0,
            })
            root  = self._parse(r)
            hosts = root.findall(".//HOST")
            dets  = sum(len(h.findall("./DETECTION_LIST/DETECTION")) for h in hosts)
        except Exception as exc:                       # diagnostic must never crash
            log.info(f"  ✘  Diagnostic call failed: {exc}")
            return
        if not hosts:
            log.info(
                "  ✘  Even without filters the API returned NO hosts.\n"
                "     → Your account sees no scanned hosts. Check the user's role /\n"
                "       asset-group scope, and that scanners or agents have completed\n"
                "       VM scans (GAV inventory alone does not create detections)."
            )
        else:
            log.info(
                f"  ✔  Unfiltered call returned {len(hosts)} host(s) / {dets} detection(s).\n"
                "     → The API works; your filters are too strict. Review\n"
                "       SEVERITY_LEVELS, DETECTION_STATUS and EXTRA_DETECTION_PARAMS."
            )

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
            if start == 0:
                _debug_save("knowledge_base_batch1", r.content)
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
    def build_cve_table(qid_hosts: dict, kb: dict) -> tuple[dict, int]:
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
                    "severity": 0, "cvss2": None, "cvss3": None,
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
                "CVE ID":             cve,
                "Affected Assets":    count,
                "QID Count":          len(e["qids"]),
                "QIDs":               ", ".join(sorted(e["qids"], key=int)),
                "Title":              e["title"],
                "Qualys Severity":    e["severity"],
                "CVSS v3":            e["cvss3"],
                "CVSS v2":            e["cvss2"],
                "CISA KEV":           "Yes" if any("cisa" in t for t in intel_lc) else "No",
                "Active Attacks":     "Yes" if any("active_attacks" in t for t in intel_lc) else "No",
                "Threat Intel Tags":  ", ".join(sorted(e["intel"])),
                "Patchable":          "Yes" if e["patchable"] else "No",
                "Published (Qualys)": e["published"],
            })

        above_threshold = len(rows)
        rows.sort(key=lambda x: (
            -x["Affected Assets"],
            -(x["CVSS v3"] or 0),
            -x["Qualys Severity"],
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
        self._check_config()

        log.info(DLINE)
        log.info("  Qualys Critical CVE Watchlist Builder  (VMDR)")
        log.info(DLINE)
        log.info(f"  Severity levels     : {SEVERITY_LEVELS}")
        log.info(f"  Detection type      : {'confirmed + potential' if INCLUDE_POTENTIAL else 'confirmed only'}")
        log.info(f"  Detection status    : {DETECTION_STATUS}")
        log.info(f"  Top N               : {TOP_N}")
        log.info(f"  Min asset count     : > {MIN_ASSET_COUNT}")
        log.info(LINE)

        self.login()

        try:
            # ── STEP 1 — FETCH DETECTIONS ─────────────────────────────────────
            log.info("\n  STEP 1 — Fetching detections (this can take a while)…\n")
            qid_hosts, hosts_returned, skipped_potential = self.fetch_detections()

            if not qid_hosts:
                log.info("\n  ✘  No usable detections found.")
                if hosts_returned == 0:
                    self.diagnose_empty()
                else:
                    log.info(
                        f"     {hosts_returned:,} host(s) were returned, but every detection was\n"
                        f"     a Potential one ({skipped_potential:,} skipped). "
                        f"Set INCLUDE_POTENTIAL = True to count them."
                    )
                return

            host_count = len(set().union(*qid_hosts.values()))
            log.info(
                f"\n  ✔  {host_count:,} host(s) with {len(qid_hosts):,} "
                f"unique QID(s) matched your filters"
                + (f"  ({skipped_potential:,} potential detection(s) skipped)"
                   if skipped_potential else "")
            )

            # ── STEP 2 — ENRICH ───────────────────────────────────────────────
            log.info("\n  STEP 2 — Enriching QIDs from the Knowledge Base…\n")
            kb = self.fetch_kb(list(qid_hosts.keys()))
            log.info(f"\n  ✔  {len(kb):,} / {len(qid_hosts):,} QID(s) resolved")
            if not kb:
                raise RuntimeError(
                    "The Knowledge Base returned no data for any QID. "
                    "Check the account has access to the Knowledge Base API "
                    "(re-run with DEBUG_SAVE_XML = True to inspect the response)."
                )

            # ── STEP 3 — RANK & FILTER ────────────────────────────────────────
            cves, no_cve_qids = self.build_cve_table(qid_hosts, kb)
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
                if not cves:
                    log.info(
                        "\n  ✘  None of the detected QIDs map to a CVE. "
                        "Nothing to export."
                    )
                    return
                ranked = sorted(cves.items(), key=lambda kv: -len(kv[1]["hosts"]))
                log.info(
                    f"\n  ✘  No CVE affects more than {MIN_ASSET_COUNT} host(s). "
                    f"Highest counts seen:\n"
                )
                log.info(f"  {'CVE ID':<16} {'Assets':>7}  Title")
                log.info(f"  {'─'*16} {'─'*7}  {'─'*40}")
                for cve, e in ranked[:10]:
                    log.info(f"  {cve:<16} {len(e['hosts']):>7}  {e['title'][:50]}")
                log.info(
                    "\n  Lower MIN_ASSET_COUNT (or set it to 0) and re-run. No file written."
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
                ("Generated (UTC)",                      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                ("Qualys platform",                      self.base_url),
                ("Severity levels",                      SEVERITY_LEVELS),
                ("Detection type",                       "confirmed + potential" if INCLUDE_POTENTIAL else "confirmed only"),
                ("Detection status",                     DETECTION_STATUS),
                ("Extra detection filters",              str(EXTRA_DETECTION_PARAMS) if EXTRA_DETECTION_PARAMS else "none"),
                ("TOP_N",                                TOP_N),
                ("MIN_ASSET_COUNT (strictly more than)", MIN_ASSET_COUNT),
                ("Hosts with matching detections",       host_count),
                ("Unique QIDs matched",                  len(qid_hosts)),
                ("Potential detections skipped",         skipped_potential),
                ("QIDs without a CVE (skipped)",         no_cve_qids),
                ("Unique CVEs found",                    len(cves)),
                ("CVEs above asset threshold",           above),
                ("CVEs exported",                        len(df)),
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
    try:
        QualysCVEWatchlist().run()
    except requests.exceptions.SSLError as exc:
        log.info(f"\n  ✘  SSL error: {exc}\n     Check CERT_PATH (or your corporate proxy certificate).\n")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        log.info(f"\n  ✘  Network error: {exc}\n     Check BASE_URL and connectivity.\n")
        sys.exit(1)
    except (ValueError, RuntimeError) as exc:      # includes QualysAPIError
        log.info(f"\n  ✘  {exc}\n")
        sys.exit(1)
