#!/usr/bin/env python3
"""
Qualys VM -> Excel exporter for a list of servers.

Sheet 1: All active vulnerabilities for the servers you enter
Sheet 2: Only VDI-related findings (RDP / Citrix / Horizon / PCoIP / ...)

Uses only Qualys VM-module APIs:
  - Host List            /api/2.0/fo/asset/host/
  - Host List Detection  /api/2.0/fo/asset/host/vm/detection/
  - KnowledgeBase        /api/2.0/fo/knowledge_base/vuln/

Run:  python qualys_vdi_export.py
Needs: pip install requests pandas openpyxl   (tkinter ships with most Python installs)
"""
from __future__ import annotations

import atexit
import getpass
import html
import json
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
import requests
import urllib3

# --------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------
SETTINGS_FILE = Path.home() / ".qualys_vdi_export.json"  # remembers everything EXCEPT the password
DEFAULT_URL = "https://qualysapi.qualys.com"
DEFAULT_OUTPUT = "Qualys_Server_VDI_Vulnerabilities.xlsx"

# API server per Qualys platform (check your pod under Help > About in the Qualys UI)
POD_URLS = [
    "https://qualysapi.qualys.com",                 # US1
    "https://qualysapi.qg2.apps.qualys.com",        # US2
    "https://qualysapi.qg3.apps.qualys.com",        # US3
    "https://qualysapi.qualys.eu",                  # EU1
    "https://qualysapi.qg2.apps.qualys.eu",         # EU2
    "https://qualysapi.qg1.apps.qualys.in",         # IN1
    "https://qualysapi.qg1.apps.qualys.ca",         # CA1
    "https://qualysapi.qg1.apps.qualys.ae",         # AE1
    "https://qualysapi.qg1.apps.qualys.co.uk",      # UK1
    "https://qualysapi.qg1.apps.qualys.com.au",     # AU1
]

HOST_CHUNK = 200      # hosts per detection request
QID_CHUNK = 250       # QIDs per KnowledgeBase request
EXCEL_CELL_MAX = 32000  # Excel hard limit is 32,767 chars per cell

# Keywords used to isolate VDI-related software & protocols for Sheet 2
VDI_KEYWORDS = [
    r"\bRDP\b",
    r"Remote Desktop",
    r"Terminal Services",
    r"Citrix",
    r"\bICA\b",
    r"\bHDX\b",
    r"Horizon",
    r"PCoIP",
    r"VMware Blast",
    r"Omnissa",
    r"\bVDI\b",
    r"Network Level Authentication",
]
VDI_REGEX = re.compile("|".join(VDI_KEYWORDS), re.IGNORECASE)

KB_COLS = ["Title", "Category", "CVSS v3", "CVEs", "Diagnosis", "Solution"]
OUTPUT_COLS = [
    "Server DNS", "NetBIOS", "IP Address", "OS", "QID", "Severity", "CVSS v3",
    "Title", "Category", "CVEs", "Port", "Protocol", "Status",
    "First Found", "Last Found", "Solution", "Detection Proof",
]


class QualysError(RuntimeError):
    pass


class GuiUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------
# HTTP / SSL
# --------------------------------------------------------------------------
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
        # Combine the default public CAs with the supplied cert, so only the
        # extra (e.g. corporate proxy) root is added instead of replacing everything.
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
        self.session = requests.Session()
        self.session.auth = (cfg["username"], cfg["password"])
        # Qualys rejects API v2 calls that lack this header
        self.session.headers.update({"X-Requested-With": "Python-Qualys-VDI-Exporter"})
        self.session.verify = resolve_verify(cfg)
        if self.session.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def post(self, endpoint: str, payload: dict, max_retries: int = 6) -> ET.Element:
        url = f"{self.base_url}{endpoint}"
        resp = None
        for attempt in range(max_retries + 1):
            resp = self.session.post(url, data=payload, timeout=(20, 900))
            # 409 = concurrency / rate limit exceeded; wait as Qualys instructs
            if resp.status_code in (409, 429, 503) and attempt < max_retries:
                wait = resp.headers.get("X-RateLimit-ToWait-Sec") or resp.headers.get("Retry-After")
                wait = int(wait) if wait and str(wait).isdigit() else min(30 * (attempt + 1), 300)
                print(f"  ... Qualys asked us to wait ({resp.status_code}); retrying in {wait + 1}s")
                time.sleep(wait + 1)
                continue
            break

        if resp.status_code == 401:
            raise QualysError("401 Unauthorized - wrong username/password, or the account has no API access.")
        if resp.status_code == 403:
            raise QualysError(f"403 Forbidden - {_error_text(resp)} (check API access / role / allowed IPs).")
        if resp.status_code >= 400:
            raise QualysError(f"HTTP {resp.status_code} from {endpoint}: {_error_text(resp)}")

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            raise QualysError(f"Unparseable response from {endpoint}: {resp.text[:200]}") from exc

        if root.tag == "SIMPLE_RETURN" and root.findtext(".//CODE"):
            raise QualysError(f"Qualys error {root.findtext('.//CODE')}: {root.findtext('.//TEXT', '')}")
        return root


# --------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_TAG = re.compile(r"<[^>]+>")


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


def parse_server_list(text: str) -> list[str]:
    seen, out = set(), []
    for item in re.split(r"[,\s;]+", text or ""):
        item = item.strip()
        if item and item.lower() not in seen:
            seen.add(item.lower())
            out.append(item)
    return out


# --------------------------------------------------------------------------
# Qualys data collection
# --------------------------------------------------------------------------
def resolve_servers(client: QualysClient, targets: list[str]):
    """Maps input names / IPs to Qualys Host IDs. Returns (matched_hosts, unmatched_inputs)."""
    wanted = {t.strip().lower() for t in targets if t.strip()}

    root = client.post(
        "/api/2.0/fo/asset/host/",
        {"action": "list", "details": "Basic", "truncation_limit": "0"},
    )

    matched, hit = {}, set()
    for host in root.findall(".//HOST_LIST/HOST"):
        host_id = host.findtext("ID", "").strip()
        ip = host.findtext("IP", "").strip()
        dns = host.findtext("DNS", "").strip()
        netbios = host.findtext("NETBIOS", "").strip()
        dns_host = host.findtext("DNS_DATA/HOSTNAME", "").strip()
        fqdn = host.findtext("DNS_DATA/FQDN", "").strip()

        names = {n.lower() for n in (dns, netbios, dns_host, fqdn) if n}
        shorts = {n.split(".")[0] for n in names}
        exact_keys = names | ({ip.lower()} if ip else set())

        for target in wanted:
            # exact FQDN / NetBIOS / IP match, or short-name match only when the input has no dots
            if target in exact_keys or ("." not in target and target in shorts):
                matched[host_id] = {
                    "host_id": host_id, "ip": ip, "dns": dns or fqdn,
                    "netbios": netbios, "os": host.findtext("OS", "").strip(),
                }
                hit.add(target)

    return matched, sorted(wanted - hit)


def fetch_detections(client: QualysClient, host_ids: list[str], include_ig: bool = False) -> list[dict]:
    detections = []
    for i in range(0, len(host_ids), HOST_CHUNK):
        chunk = host_ids[i:i + HOST_CHUNK]
        root = client.post(
            "/api/2.0/fo/asset/host/vm/detection/",
            {
                "action": "list",
                "ids": ",".join(chunk),
                "status": "New,Active,Re-Opened",
                "show_igs": "1" if include_ig else "0",
                "truncation_limit": "0",
            },
        )
        for host in root.findall(".//HOST_LIST/HOST"):
            base = {
                "Server DNS": host.findtext("DNS", "").strip(),
                "NetBIOS": host.findtext("NETBIOS", "").strip(),
                "IP Address": host.findtext("IP", "").strip(),
                "OS": host.findtext("OS", "").strip(),
            }
            if not base["Server DNS"]:
                base["Server DNS"] = host.findtext("DNS_DATA/FQDN", "").strip()
            for det in host.findall(".//DETECTION_LIST/DETECTION"):
                detections.append({
                    **base,
                    "QID": det.findtext("QID", "").strip(),
                    "Vuln Type": det.findtext("TYPE", "").strip(),
                    "Severity": int(det.findtext("SEVERITY", "0") or 0),
                    "Port": det.findtext("PORT", "").strip(),
                    "Protocol": det.findtext("PROTOCOL", "").strip(),
                    "Status": det.findtext("STATUS", "").strip(),
                    "First Found": det.findtext("FIRST_FOUND_DATETIME", "").strip(),
                    "Last Found": det.findtext("LAST_FOUND_DATETIME", "").strip(),
                    "Detection Proof": det.findtext("RESULTS", "").strip(),
                })
    return detections


def fetch_kb_metadata(client: QualysClient, qids: list[str]) -> dict:
    kb_map = {}
    for i in range(0, len(qids), QID_CHUNK):
        chunk = qids[i:i + QID_CHUNK]
        root = client.post(
            "/api/2.0/fo/knowledge_base/vuln/",
            {"action": "list", "ids": ",".join(chunk), "details": "All"},
        )
        for vuln in root.findall(".//VULN_LIST/VULN"):
            qid = vuln.findtext("QID", "").strip()
            cves = [c.text.strip() for c in vuln.findall("CVE_LIST/CVE/ID") if c.text]
            kb_map[qid] = {
                "Title": vuln.findtext("TITLE", "").strip(),
                "Category": vuln.findtext("CATEGORY", "").strip(),
                "CVSS v3": (vuln.findtext("CVSS_V3/BASE", "") or "").strip(),
                "CVEs": ", ".join(cves),
                "Diagnosis": html_to_text(vuln.findtext("DIAGNOSIS", "")),
                "Solution": html_to_text(vuln.findtext("SOLUTION", "")),
            }
    return kb_map


def is_vdi_related(row: pd.Series) -> bool:
    return bool(VDI_REGEX.search(f"{row['Title']} {row['Category']} {row['Diagnosis']}"))


# --------------------------------------------------------------------------
# Main export
# --------------------------------------------------------------------------
def run_export(cfg: dict, log=print) -> str:
    client = QualysClient(cfg)

    log("\n[1/4] Resolving server names in Qualys...")
    matched, unmatched = resolve_servers(client, cfg["servers"])
    for h in matched.values():
        log(f"  -> Matched: {h['dns'] or h['netbios']} (IP: {h['ip']}, ID: {h['host_id']})")
    for name in unmatched:
        log(f"  !! Not found in Qualys (not scanned yet, out of your scope, or different name): {name}")
    if not matched:
        raise QualysError("None of the entered servers were found in Qualys.")

    log("\n[2/4] Pulling active vulnerability detections...")
    detections = fetch_detections(client, list(matched), cfg.get("include_ig", False))
    if not detections:
        raise QualysError("The servers were found but have no active detections.")
    df_all = pd.DataFrame(detections)

    log(f"[3/4] Enriching {df_all['QID'].nunique()} unique QIDs from the KnowledgeBase...")
    kb_map = fetch_kb_metadata(client, df_all["QID"].unique().tolist())
    if not kb_map:
        log("  !! KnowledgeBase returned nothing - Title/CVE/Solution columns will be blank "
            "(check that the account has KnowledgeBase access).")
    kb_df = pd.DataFrame(
        [{"QID": q, **v} for q, v in kb_map.items()], columns=["QID"] + KB_COLS
    )
    df_all = df_all.merge(kb_df, on="QID", how="left").fillna("")
    df_all = df_all.sort_values(by=["Severity", "Server DNS", "QID"], ascending=[False, True, True])

    df_vdi = df_all[df_all.apply(is_vdi_related, axis=1)].copy()

    df_all_out = df_all[OUTPUT_COLS].copy()
    df_vdi_out = df_vdi[OUTPUT_COLS].copy()
    for frame in (df_all_out, df_vdi_out):
        for col in frame.columns:
            if frame[col].dtype == object:
                frame[col] = frame[col].map(clean_cell)

    out_path = Path(cfg.get("output_file") or DEFAULT_OUTPUT).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    log(f"[4/4] Writing {len(df_all_out)} total findings and {len(df_vdi_out)} VDI findings to {out_path} ...")
    try:
        with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
            for name, frame in (("All_Vulnerabilities", df_all_out), ("VDI_Software_Vulns", df_vdi_out)):
                frame.to_excel(writer, sheet_name=name, index=False)
                ws = writer.sheets[name]
                ws.freeze_panes = "A2"
                ws.auto_filter.ref = ws.dimensions
                for idx, col in enumerate(frame.columns, start=1):
                    longest = max([len(str(col))] + [len(str(v)) for v in frame[col].head(200)])
                    ws.column_dimensions[ws.cell(row=1, column=idx).column_letter].width = min(longest + 2, 60)
    except PermissionError as exc:
        raise QualysError(f"Cannot write {out_path} - is it open in Excel?") from exc

    log("Done.")
    return str(out_path)


# --------------------------------------------------------------------------
# Settings (password is never saved)
# --------------------------------------------------------------------------
def load_settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(cfg: dict) -> None:
    keep = ["base_url", "username", "verify_ssl", "ca_path", "append_ca", "output_file", "include_ig"]
    try:
        SETTINGS_FILE.write_text(json.dumps({k: cfg.get(k) for k in keep}, indent=2), encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Config box (Tkinter) + console fallback
# --------------------------------------------------------------------------
def get_config_gui(defaults: dict):
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        root = tk.Tk()
    except Exception as exc:  # no tkinter or no display
        raise GuiUnavailable(str(exc)) from exc

    root.title("Qualys VM - Server / VDI Vulnerability Export")
    root.resizable(False, False)

    v_url = tk.StringVar(value=defaults.get("base_url") or DEFAULT_URL)
    v_user = tk.StringVar(value=defaults.get("username") or "")
    v_pass = tk.StringVar()
    v_verify = tk.BooleanVar(value=defaults.get("verify_ssl", True))
    v_ca = tk.StringVar(value=defaults.get("ca_path") or "")
    v_append = tk.BooleanVar(value=defaults.get("append_ca", True))
    v_out = tk.StringVar(value=defaults.get("output_file") or DEFAULT_OUTPUT)
    v_ig = tk.BooleanVar(value=defaults.get("include_ig", False))
    result: dict = {}

    frm = ttk.Frame(root, padding=12)
    frm.grid(sticky="nsew")

    # --- Connection
    conn = ttk.LabelFrame(frm, text="Qualys connection", padding=8)
    conn.grid(row=0, column=0, sticky="ew")
    ttk.Label(conn, text="API URL").grid(row=0, column=0, sticky="w", pady=2)
    ttk.Combobox(conn, textvariable=v_url, values=POD_URLS, width=48).grid(row=0, column=1, columnspan=2, pady=2)
    ttk.Label(conn, text="Username").grid(row=1, column=0, sticky="w", pady=2)
    ttk.Entry(conn, textvariable=v_user, width=50).grid(row=1, column=1, columnspan=2, pady=2)
    ttk.Label(conn, text="Password").grid(row=2, column=0, sticky="w", pady=2)
    ttk.Entry(conn, textvariable=v_pass, show="*", width=50).grid(row=2, column=1, columnspan=2, pady=2)

    # --- SSL
    ssl_box = ttk.LabelFrame(frm, text="SSL verification", padding=8)
    ssl_box.grid(row=1, column=0, sticky="ew", pady=(8, 0))
    chk_verify = ttk.Checkbutton(ssl_box, text="Verify SSL certificate (recommended)", variable=v_verify)
    chk_verify.grid(row=0, column=0, columnspan=3, sticky="w")
    ttk.Label(ssl_box, text="CA cert / bundle (.pem/.crt)").grid(row=1, column=0, sticky="w", pady=2)
    ent_ca = ttk.Entry(ssl_box, textvariable=v_ca, width=38)
    ent_ca.grid(row=1, column=1, pady=2)

    def browse_ca():
        p = filedialog.askopenfilename(
            title="Select CA certificate / bundle",
            filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if p:
            v_ca.set(p)

    btn_ca = ttk.Button(ssl_box, text="Browse...", command=browse_ca)
    btn_ca.grid(row=1, column=2, padx=(4, 0))
    chk_append = ttk.Checkbutton(
        ssl_box, text="Add this cert to the default trusted CAs (untick to trust ONLY this file)",
        variable=v_append,
    )
    chk_append.grid(row=2, column=0, columnspan=3, sticky="w")
    ttk.Label(ssl_box, text="Leave the path blank to use the default CA bundle.",
              foreground="gray").grid(row=3, column=0, columnspan=3, sticky="w")

    def toggle_ssl(*_):
        state = "normal" if v_verify.get() else "disabled"
        for w in (ent_ca, btn_ca, chk_append):
            w.configure(state=state)

    v_verify.trace_add("write", toggle_ssl)
    toggle_ssl()

    # --- Servers
    srv = ttk.LabelFrame(frm, text="Servers (FQDN, NetBIOS name or IP - comma / space / new line separated)", padding=8)
    srv.grid(row=2, column=0, sticky="ew", pady=(8, 0))
    txt = tk.Text(srv, width=62, height=7)
    txt.grid(row=0, column=0)
    sb = ttk.Scrollbar(srv, command=txt.yview)
    sb.grid(row=0, column=1, sticky="ns")
    txt.configure(yscrollcommand=sb.set)
    if defaults.get("servers"):
        txt.insert("1.0", "\n".join(defaults["servers"]))

    def load_file():
        p = filedialog.askopenfilename(title="Load server list",
                                       filetypes=[("Text / CSV", "*.txt *.csv"), ("All files", "*.*")])
        if p:
            try:
                txt.insert("end", "\n" + Path(p).read_text(encoding="utf-8-sig"))
            except OSError as exc:
                messagebox.showerror("Load failed", str(exc))

    ttk.Button(srv, text="Load from file...", command=load_file).grid(row=1, column=0, sticky="w", pady=(4, 0))

    # --- Output
    out = ttk.LabelFrame(frm, text="Output", padding=8)
    out.grid(row=3, column=0, sticky="ew", pady=(8, 0))
    ttk.Entry(out, textvariable=v_out, width=52).grid(row=0, column=0)

    def browse_out():
        p = filedialog.asksaveasfilename(defaultextension=".xlsx", initialfile=v_out.get(),
                                         filetypes=[("Excel workbook", "*.xlsx")])
        if p:
            v_out.set(p)

    ttk.Button(out, text="Browse...", command=browse_out).grid(row=0, column=1, padx=(4, 0))
    ttk.Checkbutton(out, text="Include Information Gathered (IG) detections", variable=v_ig).grid(
        row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def collect(need_servers: bool):
        cfg = {
            "base_url": v_url.get().strip().rstrip("/"),
            "username": v_user.get().strip(),
            "password": v_pass.get(),
            "verify_ssl": v_verify.get(),
            "ca_path": v_ca.get().strip().strip('"'),
            "append_ca": v_append.get(),
            "output_file": v_out.get().strip() or DEFAULT_OUTPUT,
            "include_ig": v_ig.get(),
            "servers": parse_server_list(txt.get("1.0", "end")),
        }
        problems = []
        if not cfg["base_url"].lower().startswith("https://"):
            problems.append("API URL must start with https://")
        if not cfg["username"] or not cfg["password"]:
            problems.append("Username and password are required.")
        if cfg["verify_ssl"] and cfg["ca_path"] and not Path(cfg["ca_path"]).expanduser().exists():
            problems.append("The CA certificate path does not exist.")
        if need_servers and not cfg["servers"]:
            problems.append("Enter at least one server.")
        if problems:
            messagebox.showerror("Check your input", "\n".join(problems))
            return None
        return cfg

    def on_test():
        cfg = collect(need_servers=False)
        if not cfg:
            return
        root.configure(cursor="watch")
        root.update()
        try:
            QualysClient(cfg).post("/api/2.0/fo/asset/host/",
                                   {"action": "list", "details": "Basic", "truncation_limit": "1"})
            messagebox.showinfo("Connection OK", "Authenticated and the Host List API responded.")
        except requests.exceptions.SSLError as exc:
            messagebox.showerror("SSL error", f"{exc}\n\nIf you are behind a proxy that inspects HTTPS, "
                                 "point 'CA cert' at your corporate root CA (Base-64 .pem/.crt).")
        except Exception as exc:
            messagebox.showerror("Connection failed", str(exc))
        finally:
            root.configure(cursor="")

    def on_run():
        cfg = collect(need_servers=True)
        if cfg:
            result.update(cfg)
            root.destroy()

    btns = ttk.Frame(frm)
    btns.grid(row=4, column=0, sticky="e", pady=(10, 0))
    ttk.Button(btns, text="Test connection", command=on_test).grid(row=0, column=0, padx=4)
    ttk.Button(btns, text="Run export", command=on_run).grid(row=0, column=1, padx=4)
    ttk.Button(btns, text="Cancel", command=root.destroy).grid(row=0, column=2, padx=4)

    root.mainloop()
    return result or None


def get_config_cli(defaults: dict):
    print("(GUI not available - using console prompts)")
    d_url = defaults.get("base_url") or DEFAULT_URL
    base_url = input(f"Qualys API URL [{d_url}]: ").strip() or d_url
    d_user = defaults.get("username") or ""
    username = input(f"Qualys API Username [{d_user}]: ").strip() or d_user
    password = getpass.getpass("Qualys API Password: ")
    ca = input("CA cert/bundle path (blank = default CAs, 'none' = skip SSL verification): ").strip().strip('"')
    servers = parse_server_list(input("Server names (comma-separated): "))
    if not (username and password and servers):
        return None
    return {
        "base_url": base_url.rstrip("/"), "username": username, "password": password,
        "verify_ssl": ca.lower() != "none", "ca_path": "" if ca.lower() == "none" else ca,
        "append_ca": True, "output_file": defaults.get("output_file") or DEFAULT_OUTPUT,
        "include_ig": False, "servers": servers,
    }


def main() -> int:
    defaults = load_settings()
    try:
        cfg = get_config_gui(defaults)
    except GuiUnavailable:
        cfg = get_config_cli(defaults)
    if not cfg:
        print("Cancelled / incomplete input. Exiting.")
        return 1

    save_settings(cfg)
    try:
        run_export(cfg)
    except requests.exceptions.SSLError as exc:
        print(f"\nSSL error: {exc}\nUse a CA certificate path (corporate root CA) or fix the proxy trust.")
        return 2
    except (QualysError, requests.exceptions.RequestException) as exc:
        print(f"\nERROR: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
