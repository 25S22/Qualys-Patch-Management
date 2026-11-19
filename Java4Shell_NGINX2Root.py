#!/usr/bin/env python3
"""
Qualys VM -> "Which assets are affected by CVE-xxxx?" exporter.

How it works (VM module only - no CSAM / VMDR-only features needed):
  1. CVE  -> QIDs      Qualys KnowledgeBase API (with the `cve` lookup)
  2. QIDs -> assets    Host List Detection API (`qids` filter, active detections only)
  3. Scores            KnowledgeBase CVSS, per-detection QDS, and per-CVE QVS (if your subscription has it)

Output workbook (assets are NEVER duplicated - one row per Qualys Host ID):
  Sheet 1  Affected_Assets       one row per affected asset
  Sheet 2  Summary               totals + one row per CVE with risk scores
  Sheet 3  CVE_Vulnerabilities   one row per QID (vulnerability) linked to the CVE(s)

Run:  python qualys_cve_assets.py
Needs: pip install requests pandas openpyxl
"""
from __future__ import annotations

import atexit
import getpass
import html
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests
import urllib3
from requests.auth import HTTPBasicAuth

# ─────────────────────────── CONFIG ───────────────────────────
BASE_URL   = "https://qualysapi.xx.apps.qualys.in"  # Replace with your actual Qualys API URL
USERNAME   = ""     # Qualys API username. Leave blank to be prompted at run time.
PASSWORD   = ""     # Qualys API password. Leave blank to be prompted (typing is hidden).
CERT_PATH  = ""     # SSL verification:
                    #   ""  or True -> verify using the default trusted CAs
                    #   "C:\\certs\\corp-root.pem" -> also trust this Base-64 (PEM) cert/bundle
                    #   False -> do NOT verify (insecure, testing only)
APPEND_TO_DEFAULT_CAS = True  # True: CERT_PATH is added to the default CAs. False: trust ONLY that file.

# CVEs to search (comma / space separated). Blank = prompt.
# Pre-filled with the CVEs named in Qualys' own blogs:
#   Java4Shell  : CVE-2026-114938
#   NGINX2Root  : CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425
CVES = "CVE-2026-114938, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425"

# Optional: QIDs you want searched in addition to whatever the KnowledgeBase links to the CVEs.
# Useful when Qualys has published a QID in a blog but the CVE lookup does not return it yet.
# From the Qualys blogs:  Java4Shell 389494, 389610, 389608, 533508   |   NGINX2Root 736231, 389654
EXTRA_QIDS = ""

OUTPUT_FILE = "Qualys_CVE_Affected_Assets.xlsx"
INCLUDE_POTENTIAL = True   # True: count "Potential" detections too. False: Confirmed only.
KB_FALLBACK_DAYS = 180     # Only used if the KnowledgeBase `cve` lookup is rejected: scan QIDs published in the last N days
API_VERSIONS = ("3.0", "2.0")  # tried in this order for each API; the first that works is reused

QID_CHUNK = 100            # QIDs per detection request
KB_ID_CHUNK = 200          # QIDs per KnowledgeBase request
QVS_CHUNK = 50             # CVEs per QVS request
EXCEL_CELL_MAX = 32000     # Excel hard limit is 32,767 characters per cell

POD_URLS_HINT = "e.g. https://qualysapi.qg1.apps.qualys.in (India), https://qualysapi.qualys.com (US1), https://qualysapi.qualys.eu (EU1)"

KB_EP = "/api/{v}/fo/knowledge_base/vuln/"
QVS_EP = "/api/{v}/fo/knowledge_base/qvs/"
DET_EP = "/api/{v}/fo/asset/host/vm/detection/"
MANUAL_LABEL = "(manual QID)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,9}$")


class QualysError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# ─────────────────────────── HTTP / SSL ───────────────────────────
def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def resolve_verify(cfg: dict):
    """Turns the SSL settings into the value for requests' `verify=`."""
    if not cfg.get("verify_ssl", True):
        return False

    cert = (cfg.get("ca_path") or "").strip().strip('"')
    if not cert:
        return True  # default CA bundle (certifi)

    path = Path(cert).expanduser()
    if not path.exists():
        raise QualysError(f"CA certificate path not found: {path}")
    if path.is_dir():
        return str(path)

    data = path.read_bytes()
    if b"BEGIN CERTIFICATE" not in data:
        raise QualysError(
            f"{path} is not PEM (Base-64) encoded. Export the certificate as "
            "'Base-64 encoded X.509 (.CER/.PEM)' and try again."
        )

    if cfg.get("append_ca", True):
        import certifi

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        tmp.write(Path(certifi.where()).read_bytes())
        tmp.write(b"\n")
        tmp.write(data)
        tmp.close()
        atexit.register(_safe_remove, tmp.name)
        return tmp.name

    return str(path)


def _error_text(resp: requests.Response) -> str:
    try:
        root = ET.fromstring(resp.content)
        code = root.findtext(".//CODE", "") or ""
        text = root.findtext(".//TEXT", "") or ""
        return f"{code} {text}".strip() or resp.text[:300]
    except ET.ParseError:
        return resp.text[:300]


class QualysClient:
    def __init__(self, cfg: dict):
        self.base_url = cfg["base_url"].rstrip("/")
        self.username = cfg["username"]
        self._password = cfg["password"]
        self.auth = HTTPBasicAuth(cfg["username"], cfg["password"])
        self.session = requests.Session()
        # Qualys rejects API v2+ calls that lack this header
        self.session.headers.update({"X-Requested-With": "Python-Qualys-CVE-Exporter"})
        self.session.verify = resolve_verify(cfg)
        if self.session.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.versions_used: dict[str, str] = {}

    # --- session
    def login(self) -> None:
        self.post("/api/2.0/fo/session/",
                  {"action": "login", "username": self.username, "password": self._password},
                  use_auth=False)

    def logout(self) -> None:
        try:
            self.post("/api/2.0/fo/session/", {"action": "logout"}, max_retries=0)
        except Exception:
            pass

    # --- raw request with rate-limit handling
    def _send(self, endpoint: str, payload: dict, max_retries: int = 6, use_auth: bool = True,
              headers: dict | None = None) -> requests.Response:
        url = f"{self.base_url}{endpoint}"
        resp = None
        for attempt in range(max_retries + 1):
            resp = self.session.post(url, data=payload, headers=headers,
                                     auth=self.auth if use_auth else None, timeout=(20, 900))
            # 409 = concurrency / rate limit exceeded; wait as Qualys instructs
            if resp.status_code in (409, 429, 503) and attempt < max_retries:
                wait = resp.headers.get("X-RateLimit-ToWait-Sec") or resp.headers.get("Retry-After")
                wait = int(wait) if wait and str(wait).isdigit() else min(30 * (attempt + 1), 300)
                print(f"  ... Qualys asked us to wait ({resp.status_code}); retrying in {wait + 1}s")
                time.sleep(wait + 1)
                continue
            break

        if resp.status_code == 401:
            raise QualysError("401 Unauthorized - wrong username/password, or the account has no API access.", 401)
        if resp.status_code == 403:
            raise QualysError(f"403 Forbidden - {_error_text(resp)} (check API access / role / allowed IPs).", 403)
        if resp.status_code >= 400:
            raise QualysError(f"HTTP {resp.status_code} from {endpoint}: {_error_text(resp)}", resp.status_code)
        return resp

    def post(self, endpoint: str, payload: dict, max_retries: int = 6, use_auth: bool = True) -> ET.Element:
        resp = self._send(endpoint, payload, max_retries, use_auth)
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            raise QualysError(f"Unparseable response from {endpoint}: {resp.text[:200]}") from exc
        if root.tag == "SIMPLE_RETURN" and root.findtext(".//CODE"):
            raise QualysError(f"Qualys error {root.findtext('.//CODE')}: {root.findtext('.//TEXT', '')}", resp.status_code)
        return root

    def post_json(self, endpoint: str, payload: dict):
        resp = self._send(endpoint, payload, headers={"Accept": "application/json"})
        try:
            return resp.json()
        except ValueError as exc:
            raise QualysError(f"Non-JSON response from {endpoint}: {resp.text[:200]}") from exc

    def post_versioned(self, template: str, payload: dict) -> ET.Element:
        """Calls the endpoint with each API version in turn (3.0 then 2.0 by default) until one works."""
        versions = [self.versions_used[template]] if template in self.versions_used else list(API_VERSIONS)
        errors = []
        for v in versions:
            try:
                root = self.post(template.format(v=v), payload)
                self.versions_used[template] = v
                return root
            except QualysError as exc:
                errors.append(f"v{v}: {exc}")
        raise QualysError(" | ".join(errors))


# ─────────────────────────── small helpers ───────────────────────────
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_TAG = re.compile(r"<[^>]+>")


def _t(el, path: str = "") -> str:
    if el is None:
        return ""
    value = el.findtext(path) if path else el.text
    return (value or "").strip()


def _num(text) -> float | None:
    try:
        return float(str(text).strip())
    except (TypeError, ValueError):
        return None


def _int(text) -> int | None:
    n = _num(text)
    return int(n) if n is not None else None


def _max(values):
    vals = [v for v in values if v is not None]
    return max(vals) if vals else None


def html_to_text(value: str) -> str:
    if not value:
        return ""
    value = re.sub(r"<\s*(br|/p|/li|/tr)\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = _TAG.sub("", value)
    value = html.unescape(value)
    return re.sub(r"\n{3,}", "\n\n", value).strip()


def clean_cell(value):
    """Removes characters openpyxl rejects and trims to Excel's cell limit."""
    if not isinstance(value, str):
        return value
    value = _ILLEGAL_XML.sub("", value)
    if len(value) > EXCEL_CELL_MAX:
        value = value[:EXCEL_CELL_MAX] + " ...[truncated]"
    return value


def parse_cve_list(text: str) -> tuple[list[str], list[str]]:
    """Returns (valid unique CVE ids in input order, rejected tokens)."""
    good, bad, seen = [], [], set()
    for tok in re.split(r"[,\s;]+", text or ""):
        tok = tok.strip().upper()
        if not tok:
            continue
        if CVE_RE.match(tok):
            if tok not in seen:
                seen.add(tok)
                good.append(tok)
        else:
            bad.append(tok)
    return good, bad


def parse_qid_list(text: str) -> list[str]:
    seen, out = set(), []
    for tok in re.split(r"[,\s;]+", text or ""):
        if tok.isdigit() and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def to_nullable_int(df: pd.DataFrame, cols) -> None:
    """Whole-number columns that may be partly or entirely empty (e.g. no QDS / QVS available)."""
    for col in cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").round().astype("Int64")


def score_band(score) -> str:
    """Qualys QVS / QDS bands (1-100)."""
    if score is None:
        return ""
    return "Critical" if score >= 90 else "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score >= 1 else ""


def cvss_band(score) -> str:
    if score is None:
        return ""
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else ""


# ─────────────────────────── Step 1: CVE -> QIDs ───────────────────────────
def parse_kb_vulns(root: ET.Element) -> dict[str, dict]:
    out = {}
    for v in root.findall(".//VULN_LIST/VULN"):
        qid = _t(v, "QID")
        if not qid:
            continue
        patchable = _t(v, "PATCHABLE")
        out[qid] = {
            "qid": qid,
            "title": _t(v, "TITLE"),
            "category": _t(v, "CATEGORY"),
            "vuln_type": _t(v, "VULN_TYPE"),
            "severity": _int(_t(v, "SEVERITY_LEVEL")),
            "cvss2": _num(_t(v, "CVSS/BASE")),
            "cvss3": _num(_t(v, "CVSS_V3/BASE")),
            "patchable": "Yes" if patchable == "1" else "No" if patchable == "0" else "",
            "published": _t(v, "PUBLISHED_DATETIME"),
            "modified": _t(v, "LAST_SERVICE_MODIFICATION_DATETIME"),
            "cves": sorted({c.text.strip().upper() for c in v.findall("CVE_LIST/CVE/ID") if c.text and c.text.strip()}),
            "diagnosis": html_to_text(_t(v, "DIAGNOSIS")),
            "solution": html_to_text(_t(v, "SOLUTION")),
        }
    return out


def kb_by_cve(client: QualysClient, cve: str, log) -> dict[str, dict]:
    """QIDs whose CVE list contains `cve`. Always verified locally, whatever the server returned."""
    root = client.post_versioned(KB_EP, {"action": "list", "details": "All", "cve": cve})
    vulns = parse_kb_vulns(root)
    matched = {q: v for q, v in vulns.items() if cve in v["cves"]}
    extra = len(vulns) - len(matched)
    if extra > 200:
        log(f"  (note: Qualys returned {extra} unrelated QIDs for {cve}; the filter was ignored, "
            f"results were filtered locally so they are still correct)")
    return matched


def kb_scan_recent(client: QualysClient, wanted: set[str], days: int, log) -> dict[str, dict]:
    """Fallback when the `cve` lookup is rejected: walk QIDs published in the last N days in 30-day windows."""
    today = datetime.now(timezone.utc).date()
    cur = today - timedelta(days=days)
    found = {}
    while cur <= today:
        nxt = min(cur + timedelta(days=30), today + timedelta(days=1))
        root = client.post_versioned(KB_EP, {
            "action": "list", "details": "All",
            "published_after": f"{cur.isoformat()}T00:00:00Z",
            "published_before": f"{nxt.isoformat()}T00:00:00Z",
        })
        for qid, v in parse_kb_vulns(root).items():
            if wanted & set(v["cves"]):
                found[qid] = v
        log(f"    scanned QIDs published {cur} -> {nxt}: {len(found)} relevant so far")
        if nxt > today:
            break
        cur = nxt - timedelta(days=1)  # 1-day overlap so nothing on a window edge is missed
    return found


def kb_by_ids(client: QualysClient, qids: list[str]) -> dict[str, dict]:
    out = {}
    for chunk in chunks(qids, KB_ID_CHUNK):
        root = client.post_versioned(KB_EP, {"action": "list", "details": "All", "ids": ",".join(chunk)})
        out.update(parse_kb_vulns(root))
    return out


def map_cves_to_qids(client: QualysClient, cves: list[str], extra_qids: list[str], log):
    """Returns (kb {qid: info}, qid_cves {qid: [labels]}, cve_to_qids {cve: [qid]}, notes)."""
    kb: dict[str, dict] = {}
    notes: list[str] = []
    rejected = None

    for cve in cves:
        try:
            found = kb_by_cve(client, cve, log)
        except QualysError as exc:
            rejected = str(exc)
            break
        kb.update(found)
        log(f"  {cve}: {len(found)} QID(s) {sorted(found) if found else ''}")

    if rejected is not None:
        log(f"  !! KnowledgeBase CVE lookup was rejected ({rejected})")
        log(f"  -> falling back to scanning QIDs published in the last {KB_FALLBACK_DAYS} days")
        kb = kb_scan_recent(client, set(cves), KB_FALLBACK_DAYS, log)
        notes.append(f"KnowledgeBase CVE lookup unavailable; searched QIDs published in the last {KB_FALLBACK_DAYS} days instead "
                     f"(older QIDs for these CVEs would be missed - add them to EXTRA_QIDS).")

    manual = set()
    if extra_qids:
        fetched = kb_by_ids(client, extra_qids)
        missing = [q for q in extra_qids if q not in fetched]
        if missing:
            log(f"  !! EXTRA_QIDS not found in your KnowledgeBase: {', '.join(missing)}")
            notes.append(f"EXTRA_QIDS not found in KnowledgeBase: {', '.join(missing)}")
        for qid, info in fetched.items():
            if qid not in kb:
                manual.add(qid)
            kb[qid] = info

    requested = set(cves)
    qid_cves: dict[str, list[str]] = {}
    cve_to_qids: dict[str, list[str]] = {c: [] for c in cves}
    for qid, info in kb.items():
        hit = sorted(requested & set(info["cves"]))
        if hit:
            qid_cves[qid] = hit
            for c in hit:
                cve_to_qids[c].append(qid)
        else:
            qid_cves[qid] = [MANUAL_LABEL]  # only reachable through EXTRA_QIDS
    for c in cve_to_qids:
        cve_to_qids[c].sort(key=int)
    return kb, qid_cves, cve_to_qids, notes


# ─────────────────────────── Step 2: risk scores ───────────────────────────
def _flat(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(_flat(v)) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_flat(v)}" for k, v in value.items())
    return str(value)


def parse_qvs(data, depth: int = 0) -> dict[str, dict]:
    out: dict[str, dict] = {}
    items = data.items() if isinstance(data, dict) else enumerate(data) if isinstance(data, list) else []
    for key, val in items:
        if not isinstance(val, dict):
            continue
        base = val.get("base") if isinstance(val.get("base"), dict) else None
        if base is not None:
            cve = str(base.get("id") or key).upper()
            if CVE_RE.match(cve):
                cf = val.get("contributingFactors") or {}
                out[cve] = {
                    "qvs": _num(base.get("qvs")),
                    "epss": _flat(cf.get("epss")),
                    "exploit": _flat(cf.get("exploitMaturity")),
                    "cisa": _flat(cf.get("cisaVuln")),
                    "trending": _flat(cf.get("trending")),
                }
        elif depth < 2:
            out.update(parse_qvs(val, depth + 1))
    return out


def fetch_qvs(client: QualysClient, cves: list[str], log) -> tuple[dict[str, dict], str]:
    """Qualys Vulnerability Score per CVE. Returns (scores, source/note)."""
    scores: dict[str, dict] = {}
    last_err = ""
    for v, param in (("3.0", "cve"), ("2.0", "CVEs")):
        try:
            scores = {}
            for chunk in chunks(cves, QVS_CHUNK):
                data = client.post_json(QVS_EP.format(v=v),
                                        {"action": "list", param: ",".join(chunk), "details": "All"})
                scores.update(parse_qvs(data))
            if scores:
                return scores, f"Qualys KnowledgeBase QVS API v{v}"
            last_err = f"v{v}: returned no scores for these CVEs"
        except QualysError as exc:
            last_err = f"v{v}: {exc}"
    return {}, f"not available ({last_err})"


# ─────────────────────────── Step 3: detections (QID -> assets) ───────────────────────────
def next_id_min(root: ET.Element) -> str | None:
    url = root.findtext(".//WARNING/URL") or ""
    m = re.search(r"[?&]id_min=(\d+)", url)
    return m.group(1) if m else None


def fetch_detections(client: QualysClient, qids: list[str], log) -> tuple[dict[str, dict], bool]:
    """Returns ({host_id: host + detections}, qds_available). Pages through every host."""
    hosts: dict[str, dict] = {}
    use_qds = True
    for chunk in chunks(qids, QID_CHUNK):
        payload = {"action": "list", "qids": ",".join(chunk), "status": "New,Active,Re-Opened",
                   "show_igs": "1", "show_results": "0", "truncation_limit": "1000"}
        page = 1
        while True:
            req = dict(payload)
            if use_qds:
                req["show_qds"] = "1"
            try:
                root = client.post_versioned(DET_EP, req)
            except QualysError as exc:
                if use_qds:
                    log(f"  !! request with show_qds=1 failed ({exc}); retrying without QDS scores")
                    use_qds = False
                    continue
                raise

            n = 0
            for host in root.findall(".//HOST_LIST/HOST"):
                host_id = _t(host, "ID")
                if not host_id:
                    continue
                n += 1
                h = hosts.setdefault(host_id, {"host_id": host_id, "dets": []})
                for key, path in (("dns", "DNS"), ("netbios", "NETBIOS"), ("ip", "IP"), ("os", "OS"),
                                  ("tracking", "TRACKING_METHOD"), ("fqdn", "DNS_DATA/FQDN"),
                                  ("last_scan", "LAST_VM_SCANNED_DATE")):
                    if not h.get(key):
                        h[key] = _t(host, path)
                if not h.get("last_scan"):
                    h["last_scan"] = _t(host, "LAST_SCAN_DATETIME")
                for det in host.findall(".//DETECTION_LIST/DETECTION"):
                    h["dets"].append({
                        "qid": _t(det, "QID"),
                        "type": _t(det, "TYPE"),
                        "severity": _int(_t(det, "SEVERITY")),
                        "status": _t(det, "STATUS"),
                        "first": _t(det, "FIRST_FOUND_DATETIME"),
                        "last": _t(det, "LAST_FOUND_DATETIME"),
                        "qds": _int(_t(det, "QDS")),
                    })
            log(f"    QIDs {chunk[0]}..{chunk[-1]} page {page}: {n} host(s)")
            nxt = next_id_min(root)
            if nxt and nxt != payload.get("id_min"):
                payload["id_min"] = nxt
                page += 1
                continue
            break
    return hosts, use_qds


# ─────────────────────────── Step 4: dedupe + aggregate ───────────────────────────
def build_outputs(cves, kb, qid_cves, cve_to_qids, hosts, qvs, qvs_note, qds_ok, include_potential, notes, base_url):
    wanted_qids = set(kb)

    # ---- one row per Host ID (dedupe): a host's detections are merged, never listed twice
    asset_rows = []
    host_cves: dict[str, set] = {}
    qid_assets: dict[str, set] = {q: set() for q in kb}
    cve_assets: dict[str, set] = {c: set() for c in cves}
    cve_conf: dict[str, set] = {c: set() for c in cves}
    cve_qds: dict[str, list] = {c: [] for c in cves}
    cve_dets: dict[str, int] = {c: 0 for c in cves}

    for host_id, h in hosts.items():
        dets = [d for d in h["dets"]
                if d["qid"] in wanted_qids and (include_potential or d["type"].lower() != "potential")]
        if not dets:
            continue
        qids = sorted({d["qid"] for d in dets}, key=int)
        labels = sorted({lab for q in qids for lab in qid_cves[q]})
        types = {d["type"] for d in dets if d["type"]}
        firsts = [d["first"] for d in dets if d["first"]]
        lasts = [d["last"] for d in dets if d["last"]]
        max_qds = _max(d["qds"] for d in dets)
        for q in qids:
            qid_assets[q].add(host_id)
        for d in dets:
            for lab in qid_cves[d["qid"]]:
                if lab in cve_assets:
                    cve_assets[lab].add(host_id)
                    cve_dets[lab] += 1
                    cve_qds[lab].append(d["qds"])
                    if d["type"].lower() != "potential":
                        cve_conf[lab].add(host_id)
        host_cves[host_id] = set(labels)
        asset_rows.append({
            "Host ID": int(host_id) if host_id.isdigit() else host_id,
            "Server DNS": h.get("dns") or h.get("fqdn", ""),
            "NetBIOS": h.get("netbios", ""),
            "IP Address": h.get("ip", ""),
            "OS": h.get("os", ""),
            "Tracking Method": h.get("tracking", ""),
            "Last VM Scan": h.get("last_scan", ""),
            "Affected CVEs": "; ".join(labels),
            "# CVEs": len([x for x in labels if x != MANUAL_LABEL]),
            "QIDs": "; ".join(qids),
            "# QIDs": len(qids),
            "Highest Severity": _max(d["severity"] for d in dets),
            "Highest QDS": max_qds,
            "QDS Rating": score_band(max_qds),
            "Detection Type": " + ".join(sorted(types)),
            "Status": "; ".join(sorted({d["status"] for d in dets if d["status"]})),
            "Earliest First Found": min(firsts) if firsts else "",
            "Latest Last Found": max(lasts) if lasts else "",
        })

    # flag (not merge) assets whose hostname also appears under another Host ID
    by_name: dict[str, set] = {}
    for r in asset_rows:
        name = (r["Server DNS"] or r["NetBIOS"]).strip().lower()
        if name:
            by_name.setdefault(name, set()).add(str(r["Host ID"]))
    for r in asset_rows:
        name = (r["Server DNS"] or r["NetBIOS"]).strip().lower()
        r["Possible Duplicate Record"] = "Yes" if name and len(by_name[name]) > 1 else "No"

    asset_cols = ["Host ID", "Server DNS", "NetBIOS", "IP Address", "OS", "Tracking Method", "Last VM Scan",
                  "Affected CVEs", "# CVEs", "QIDs", "# QIDs", "Highest Severity", "Highest QDS", "QDS Rating",
                  "Detection Type", "Status", "Earliest First Found", "Latest Last Found", "Possible Duplicate Record"]
    df_assets = pd.DataFrame(asset_rows, columns=asset_cols)
    if not df_assets.empty:
        df_assets["_q"] = pd.to_numeric(df_assets["Highest QDS"], errors="coerce").fillna(-1)
        df_assets["_s"] = pd.to_numeric(df_assets["Highest Severity"], errors="coerce").fillna(-1)
        df_assets = df_assets.sort_values(["_s", "_q", "Server DNS", "Host ID"],
                                          ascending=[False, False, True, True]).drop(columns=["_s", "_q"])
    to_nullable_int(df_assets, ("# CVEs", "# QIDs", "Highest Severity", "Highest QDS"))

    # ---- Sheet 3: one row per QID
    vuln_rows = []
    for qid, info in kb.items():
        vuln_rows.append({
            "CVE(s) Searched": "; ".join(qid_cves[qid]),
            "QID": int(qid),
            "Title": info["title"],
            "Vuln Type": info["vuln_type"],
            "Severity": info["severity"],
            "Category": info["category"],
            "CVSS v3 Base": info["cvss3"],
            "CVSS v2 Base": info["cvss2"],
            "Patchable": info["patchable"],
            "Published": info["published"],
            "Last Modified": info["modified"],
            "Unique Affected Assets": len(qid_assets[qid]),
            "All CVEs on this QID": ", ".join(info["cves"]),
            "Solution": info["solution"],
        })
    vuln_cols = ["CVE(s) Searched", "QID", "Title", "Vuln Type", "Severity", "Category", "CVSS v3 Base", "CVSS v2 Base",
                 "Patchable", "Published", "Last Modified", "Unique Affected Assets", "All CVEs on this QID", "Solution"]
    df_vulns = pd.DataFrame(vuln_rows, columns=vuln_cols)
    if not df_vulns.empty:
        df_vulns["_s"] = pd.to_numeric(df_vulns["Severity"], errors="coerce").fillna(-1)
        df_vulns = df_vulns.sort_values(["_s", "Unique Affected Assets", "QID"],
                                        ascending=[False, False, True]).drop(columns=["_s"])
    to_nullable_int(df_vulns, ("QID", "Severity", "Unique Affected Assets"))

    # ---- Sheet 2: summary
    cve_rows = []
    labels = list(cves) + ([MANUAL_LABEL] if any(MANUAL_LABEL in v for v in qid_cves.values()) else [])
    if MANUAL_LABEL in labels:
        cve_assets[MANUAL_LABEL], cve_conf[MANUAL_LABEL] = set(), set()
        cve_qds[MANUAL_LABEL], cve_dets[MANUAL_LABEL] = [], 0
        cve_to_qids[MANUAL_LABEL] = sorted((q for q, v in qid_cves.items() if MANUAL_LABEL in v), key=int)
        for hid, hc in host_cves.items():
            if MANUAL_LABEL in hc:
                cve_assets[MANUAL_LABEL].add(hid)
        for h_id in cve_assets[MANUAL_LABEL]:
            if any(d["type"].lower() != "potential" and MANUAL_LABEL in qid_cves.get(d["qid"], [])
                   for d in hosts[h_id]["dets"]):
                cve_conf[MANUAL_LABEL].add(h_id)
    for c in labels:
        qids = cve_to_qids.get(c, [])
        score = qvs.get(c, {})
        qvs_val = score.get("qvs")
        max_qds = _max(cve_qds[c])
        cvss3 = _max(kb[q]["cvss3"] for q in qids)
        cvss2 = _max(kb[q]["cvss2"] for q in qids)
        if qvs_val is not None:
            rating, basis = score_band(qvs_val), "QVS"
        elif max_qds is not None:
            rating, basis = score_band(max_qds), "QDS"
        elif cvss3 is not None:
            rating, basis = cvss_band(cvss3), "CVSS v3"
        elif cvss2 is not None:
            rating, basis = cvss_band(cvss2), "CVSS v2"
        else:
            rating, basis = "", ""
        if not qids:
            note = ("No QID in your Qualys KnowledgeBase links to this CVE yet - Qualys may not have released a detection, "
                    "or your KnowledgeBase has not synced. Re-run after the next signature update, or add the QID from "
                    "the Qualys blog to EXTRA_QIDS.")
        elif not cve_assets[c]:
            note = "QID(s) exist but no active detections on any asset you can see."
        else:
            note = ""
        cve_rows.append({
            "CVE": c,
            "Unique Affected Assets": len(cve_assets[c]),
            "Assets with Confirmed Detection": len(cve_conf[c]),
            "QIDs": "; ".join(qids),
            "# QIDs": len(qids),
            "Highest Qualys Severity (1-5)": _max(kb[q]["severity"] for q in qids),
            "CVSS v3 Base (max)": cvss3,
            "CVSS v2 Base (max)": cvss2,
            "QVS (1-100)": qvs_val,
            "Exploit Maturity": score.get("exploit", ""),
            "EPSS": score.get("epss", ""),
            "CISA KEV": score.get("cisa", ""),
            "Max QDS on assets (1-100)": max_qds,
            "Risk Rating": rating,
            "Rating Basis": basis,
            "Note": note,
        })
    cve_cols = ["CVE", "Unique Affected Assets", "Assets with Confirmed Detection", "QIDs", "# QIDs",
                "Highest Qualys Severity (1-5)", "CVSS v3 Base (max)", "CVSS v2 Base (max)", "QVS (1-100)",
                "Exploit Maturity", "EPSS", "CISA KEV", "Max QDS on assets (1-100)", "Risk Rating", "Rating Basis", "Note"]
    df_cve = pd.DataFrame(cve_rows, columns=cve_cols)
    to_nullable_int(df_cve, ("Unique Affected Assets", "Assets with Confirmed Detection", "# QIDs",
                             "Highest Qualys Severity (1-5)", "QVS (1-100)", "Max QDS on assets (1-100)"))

    total_assets = len(df_assets)
    meta = [
        ("Report generated (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        ("Qualys API server", base_url),
        ("CVEs searched", len(cves)),
        ("CVEs with at least one QID in the KnowledgeBase", sum(1 for c in cves if cve_to_qids.get(c))),
        ("Unique QIDs (vulnerabilities) matched", len(kb)),
        ("TOTAL UNIQUE AFFECTED ASSETS (all CVEs, counted once)", total_assets),
        ("  - with a Confirmed detection", sum(1 for r in asset_rows if "Confirmed" in r["Detection Type"])),
        ("  - Potential detections only", sum(1 for r in asset_rows if "Confirmed" not in r["Detection Type"])),
        ("Assets flagged 'Possible Duplicate Record'", int((df_assets["Possible Duplicate Record"] == "Yes").sum()) if total_assets else 0),
        ("Potential detections", "included" if include_potential else "excluded (Confirmed only)"),
        ("QVS (per-CVE score) source", qvs_note),
        ("QDS (per-asset score)", "returned by Qualys" if qds_ok else "not available for this account"),
    ]
    for n in notes:
        meta.append(("Note", n))
    meta.append(("Note", "Each asset is counted once per Qualys Host ID, even if it is hit by several QIDs, CVEs or ports. "
                         "Per-CVE counts overlap (one asset can be in several CVEs), so they do not add up to the total."))
    meta.append(("Note", "Results reflect the latest scan / agent data in Qualys. An asset not scanned since the QID was "
                         "released will not appear yet."))
    df_meta = pd.DataFrame(meta, columns=["Metric", "Value"])
    return df_assets, df_meta, df_cve, df_vulns


# ─────────────────────────── Step 5: Excel ───────────────────────────
def _style_and_size(ws, header_rows: list[int]):
    from openpyxl.styles import Alignment, Font, PatternFill

    fill = PatternFill("solid", fgColor="1F3864")
    for r in header_rows:
        for cell in ws[r]:
            if cell.value is not None:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = fill
                cell.alignment = Alignment(vertical="center", wrap_text=True)
    widths: dict[int, int] = {}
    for row in ws.iter_rows(min_row=1, max_row=min(ws.max_row, 400)):
        for cell in row:
            if cell.value is not None:
                longest = max(len(line) for line in str(cell.value).split("\n"))
                widths[cell.column] = max(widths.get(cell.column, 0), longest)
    for col, w in widths.items():
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = min(max(w + 2, 8), 60)


def write_workbook(path: Path, df_assets, df_meta, df_cve, df_vulns):
    frames = []
    for df in (df_assets, df_meta, df_cve, df_vulns):
        frames.append(df.apply(lambda col: col.map(clean_cell)))
    df_assets, df_meta, df_cve, df_vulns = frames

    path.parent.mkdir(parents=True, exist_ok=True)
    cve_header_row = len(df_meta) + 4  # 1-based row of the per-CVE header
    try:
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            df_assets.to_excel(writer, sheet_name="Affected_Assets", index=False)
            df_meta.to_excel(writer, sheet_name="Summary", index=False, startrow=0)
            df_cve.to_excel(writer, sheet_name="Summary", index=False, startrow=len(df_meta) + 3)
            df_vulns.to_excel(writer, sheet_name="CVE_Vulnerabilities", index=False)

            ws = writer.sheets["Affected_Assets"]
            _style_and_size(ws, [1])
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = ws.dimensions

            ws = writer.sheets["Summary"]
            _style_and_size(ws, [1, cve_header_row])
            from openpyxl.styles import Alignment, Font
            for r in range(2, len(df_meta) + 2):
                ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
                ws.cell(row=r, column=2).alignment = Alignment(wrap_text=True, vertical="top", horizontal="left")
                if str(ws.cell(row=r, column=1).value).startswith("TOTAL"):
                    ws.cell(row=r, column=1).font = Font(bold=True)
                    ws.cell(row=r, column=2).font = Font(bold=True)

            ws = writer.sheets["CVE_Vulnerabilities"]
            _style_and_size(ws, [1])
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = ws.dimensions
    except PermissionError as exc:
        raise QualysError(f"Cannot write {path} - is it open in Excel?") from exc


# ─────────────────────────── main flow ───────────────────────────
def run_export(cfg: dict, log=print) -> str:
    client = QualysClient(cfg)
    log(f"\n[0/5] Logging in to {client.base_url} as {cfg['username']} ...")
    client.login()
    log("  Login successful.")
    try:
        return _export(client, cfg, log)
    finally:
        client.logout()


def _export(client: QualysClient, cfg: dict, log) -> str:
    cves = cfg["cves"]
    log(f"\n[1/5] Finding the QIDs (Qualys detections) linked to {len(cves)} CVE(s)...")
    kb, qid_cves, cve_to_qids, notes = map_cves_to_qids(client, cves, cfg.get("extra_qids", []), log)
    for c in cves:
        if not cve_to_qids.get(c):
            log(f"  !! {c}: no QID in your KnowledgeBase links to this CVE (yet)")

    log("\n[2/5] Fetching risk scores (QVS) for the CVEs...")
    qvs, qvs_note = fetch_qvs(client, cves, log)
    log(f"  QVS: {qvs_note}" + (f" - {len(qvs)} CVE(s) scored" if qvs else ""))

    hosts, qds_ok = {}, True
    if kb:
        log(f"\n[3/5] Pulling active detections for {len(kb)} QID(s) across all assets you can see...")
        hosts, qds_ok = fetch_detections(client, sorted(kb, key=int), log)
    else:
        log("\n[3/5] No QIDs to search - skipping the detection pull.")

    log("\n[4/5] De-duplicating per asset and building the report...")
    df_assets, df_meta, df_cve, df_vulns = build_outputs(
        cves, kb, qid_cves, cve_to_qids, hosts, qvs, qvs_note, qds_ok,
        cfg.get("include_potential", True), notes, client.base_url)
    log(f"  {len(df_assets)} unique affected asset(s); {len(df_vulns)} unique QID(s)")

    out_path = Path(cfg.get("output_file") or OUTPUT_FILE).expanduser()
    log(f"\n[5/5] Writing {out_path} ...")
    write_workbook(out_path, df_assets, df_meta, df_cve, df_vulns)
    names = {KB_EP: "KnowledgeBase", DET_EP: "Detection"}
    if client.versions_used:
        log("  API versions used: " + ", ".join(f"{names.get(k, k)} v{v}" for k, v in client.versions_used.items()))
    log("Done.")
    return str(out_path)


# ─────────────────────────── config + prompts ───────────────────────────
_PLACEHOLDERS = {"", "username", "password"}


def build_cfg_from_config() -> dict:
    ca = CERT_PATH if isinstance(CERT_PATH, str) else ""
    cves, bad = parse_cve_list(CVES)
    return {
        "base_url": (BASE_URL or "").strip().rstrip("/"),
        "username": "" if (USERNAME or "").strip().lower() in _PLACEHOLDERS else USERNAME.strip(),
        "password": "" if (PASSWORD or "").strip().lower() in _PLACEHOLDERS else PASSWORD,
        "verify_ssl": CERT_PATH is not False,
        "ca_path": ca.strip().strip('"'),
        "append_ca": APPEND_TO_DEFAULT_CAS,
        "output_file": OUTPUT_FILE,
        "include_potential": INCLUDE_POTENTIAL,
        "cves": cves,
        "bad_cves": bad,
        "extra_qids": parse_qid_list(EXTRA_QIDS),
    }


def prompt_missing(cfg: dict) -> dict:
    if not cfg["base_url"] or ".xx." in cfg["base_url"]:
        cfg["base_url"] = input(f"Qualys API URL ({POD_URLS_HINT}): ").strip().rstrip("/")
    if not cfg["username"]:
        cfg["username"] = input("Qualys API Username: ").strip()
    if not cfg["password"]:
        cfg["password"] = getpass.getpass("Qualys API Password: ")
    if cfg["verify_ssl"] and not cfg["ca_path"] and not CERT_PATH:
        cfg["ca_path"] = input("SSL cert path (.pem/.crt) - press Enter to use default CAs: ").strip().strip('"')
    if not cfg["cves"]:
        cves, bad = parse_cve_list(input("CVE IDs to search (comma-separated, e.g. CVE-2026-114938): "))
        cfg["cves"], cfg["bad_cves"] = cves, cfg["bad_cves"] + bad
    return cfg


def main() -> int:
    cfg = prompt_missing(build_cfg_from_config())
    if cfg["bad_cves"]:
        print(f"Ignoring entries that are not valid CVE IDs: {', '.join(cfg['bad_cves'])}")
    if not all(cfg.get(k) for k in ("base_url", "username", "password", "cves")):
        print("Missing URL, credentials or CVE list. Exiting.")
        return 1
    try:
        run_export(cfg)
    except requests.exceptions.SSLError as exc:
        print(f"\nSSL error: {exc}\nSet CERT_PATH to your corporate root CA (Base-64 .pem/.crt).")
        return 2
    except (QualysError, requests.exceptions.RequestException) as exc:
        print(f"\nERROR: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
