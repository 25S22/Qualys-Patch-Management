"""
Qualys Asset Purge Script
Matches stopped/terminated EC2 instances from input files against Qualys assets,
then optionally purges them.
"""

import time
import os
import sys
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Tuple

import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ─────────────────────────── CONFIG ───────────────────────────
BASE_URL   = "https://qualysapi.xx.apps.qualys.in"  # Replace with your actual Qualys URL
FILEPATH   = "C:\\mycode\\CS\\test"                  # Folder containing your EC2 CSV/Excel files
BATCH_SIZE = 50
USERNAME   = "username"    # Replace with real creds
PASSWORD   = "password"    # Replace with real creds
PAGE_SIZE  = 1000
CERT_PATH  = True           # Set to path like "C:\\cert.pem" or True to skip verification
ASSET_ID_COL  = "Asset ID"
EC2_RAW_COL   = "sourceInfo.list.Ec2AssetSourceSimple.instanceId"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ─────────────────────────── AUTH ───────────────────────────
def login(session: requests.Session) -> None:
    """Login to Qualys and store session cookie."""
    response = session.post(
        f"{BASE_URL}/api/2.0/fo/session/",
        headers={"X-Requested-With": "Python"},
        data={"action": "login", "username": USERNAME, "password": PASSWORD},
        verify=CERT_PATH
    )
    response.raise_for_status()
    if "QualysSession" not in session.cookies:
        raise Exception("Login failed: QualysSession cookie not found")
    log.info("Login successful")


def logout(session: requests.Session) -> None:
    """Logout from Qualys."""
    try:
        session.post(
            f"{BASE_URL}/api/2.0/fo/session/",
            headers={"X-Requested-With": "Python"},
            data={"action": "logout"},
            verify=CERT_PATH
        )
        log.info("Logout successful")
    except Exception:
        pass


# ─────────────────────────── SESSION HELPER ───────────────────────────
def generate_session(session: requests.Session, endpoint: str, body: bytes) -> requests.Response:
    """POST XML request to a Qualys API endpoint."""
    response = session.post(
        f"{BASE_URL}{endpoint}",
        headers={"Content-Type": "application/xml", "Accept": "application/xml"},
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        data=body,
        verify=CERT_PATH
    )
    response.raise_for_status()
    return response


# ─────────────────────────── VERIFY ASSETS ───────────────────────────
def build_verify_request(asset_ids: List[str]) -> bytes:
    """Build XML body to look up assets by ID."""
    xml = f"""<ServiceRequest>
  <filters>
    <Criteria field="id" operator="IN">
      {",".join(asset_ids)}
    </Criteria>
  </filters>
</ServiceRequest>"""
    return xml.encode("utf-8")


def verify_assets(session: requests.Session, asset_ids: List[str]) -> Dict[str, dict]:
    """Verify which asset IDs exist in Qualys. Returns dict keyed by asset ID."""
    results = {}
    for start in range(0, len(asset_ids), BATCH_SIZE):
        batch = asset_ids[start:start + BATCH_SIZE]
        response = generate_session(session, "/qps/rest/2.0/search/am/hostasset", build_verify_request(batch))
        root = ET.fromstring(response.content)
        assets = root.findall(".//HostAsset")
        for asset in assets:
            asset_id = asset.findtext("id", "").strip()
            hostname = (
                asset.findtext("dnsHostName", "").strip()
                or asset.findtext("netbiosName", "").strip()
            )
            ip = asset.findtext("address", "").strip()
            results[asset_id] = {"found": True, "hostname": hostname, "ip": ip}
        time.sleep(0.2)
    return results


# ─────────────────────────── DELETE / PURGE ───────────────────────────
def build_delete_request(asset_ids: List[str]) -> bytes:
    """Build XML body to delete assets by ID."""
    xml = f"""<ServiceRequest>
  <filters>
    <Criteria field="id" operator="IN">
      {",".join(asset_ids)}
    </Criteria>
  </filters>
</ServiceRequest>"""
    return xml.encode("utf-8")


def purge_batch(session: requests.Session, asset_ids: List[str]) -> List[str]:
    """Purge a single batch of assets. Returns list of deleted IDs."""
    response = generate_session(session, "/qps/rest/2.0/delete/am/hostasset", build_delete_request(asset_ids))
    root = ET.fromstring(response.content)
    response_code = root.findtext(".//responseCode", "")
    if response_code == "SUCCESS":
        return asset_ids
    return []


def purge_assets(session: requests.Session, asset_ids: List[str]) -> List[str]:
    """Purge all assets in batches. Returns list of all deleted IDs."""
    deleted = []
    for start in range(0, len(asset_ids), BATCH_SIZE):
        batch = asset_ids[start:start + BATCH_SIZE]
        deleted.extend(purge_batch(session, batch))
        time.sleep(0.5)
    return deleted


# ─────────────────────────── INPUT FILE READING ───────────────────────────
def get_dead_instance_dicts(
    filepath: str,
    id_column: str = "Resource ID",
    status_column: str = "State"
) -> List[Dict]:
    """
    Read all CSV/Excel files from filepath, return only TERMINATED instances.

    Deliberately excludes 'stopped' instances — stopped instances may be
    intentionally powered off and restarted later, so purging them from
    Qualys would cause them to reappear as new untracked assets on next boot.
    Only 'terminated' instances are permanently gone and safe to purge.
    """
    files_data = {}
    all_data = pd.DataFrame()

    for filename in os.listdir(filepath):
        file_path = os.path.join(filepath, filename)
        try:
            if filename.endswith(".xlsx") or filename.endswith(".xls"):
                df = pd.read_excel(file_path)
                files_data[filename] = df
                log.info(f"Read Excel file: {filename}")
            elif filename.endswith(".csv"):
                df = pd.read_csv(file_path)
                files_data[filename] = df
                log.info(f"Read CSV file: {filename}")
            else:
                continue
            all_data = pd.concat([all_data, df], ignore_index=True)
        except Exception as e:
            log.error(f"Error reading file {filename}: {str(e)}")

    if all_data.empty:
        log.warning("No data loaded from input files")
        return []

    # Exact match on "terminated" only — strip whitespace, lowercase both sides
    # Previously used str.contains("stopped|terminated") which caught stopped too
    terminated_mask = (
        all_data[status_column]
        .astype(str)
        .str.strip()
        .str.lower()
        == "terminated"
    )
    dead_df     = all_data[terminated_mask]
    result_list = dead_df[[id_column, status_column]].to_dict(orient="records")
    log.info(f"Terminated instances found in files: {len(result_list)}")
    return result_list


# ─────────────────────────── FETCH ALL HOSTS ───────────────────────────
def build_ec2_fetch_request(last_id: str = None) -> bytes:
    """
    Build a filtered XML request for EC2 assets using cursor-based pagination.

    WHY startFromId INSTEAD OF startFromOffset:
    ─────────────────────────────────────────────
    Qualys silently caps how many records it returns per page when a
    filter is active — often far below the limitResults value (e.g. 160
    records even when limitResults=1000). Using startFromOffset would
    mean the next request jumps to offset 1001, skipping records 161–1000
    entirely, then returns empty and stops.

    startFromId tells Qualys "give me the next page starting after this
    asset ID". It is not affected by the per-page cap and guarantees
    every record is fetched exactly once regardless of how many Qualys
    decides to return per batch.
    """
    root = ET.Element("ServiceRequest")

    filters  = ET.SubElement(root, "filters")
    criteria = ET.SubElement(filters, "Criteria")
    criteria.set("field",    "trackingMethod")
    criteria.set("operator", "EQUALS")
    criteria.text = "INSTANCE_ID"

    preferences = ET.SubElement(root, "preferences")
    if last_id:
        # cursor-based: pick up from the ID after the last one we received
        ET.SubElement(preferences, "startFromId").text = str(last_id)
    else:
        # first page — no cursor yet
        ET.SubElement(preferences, "startFromOffset").text = "1"
    ET.SubElement(preferences, "limitResults").text = str(PAGE_SIZE)
    return ET.tostring(root, encoding="utf-8")


def fetch_all_hosts(session: requests.Session) -> List[ET.Element]:
    """
    Fetch all EC2 HostAsset records from Qualys using cursor-based pagination.

    Uses startFromId (not startFromOffset) so no records are skipped
    when Qualys returns fewer items per page than limitResults.
    """
    url      = f"{BASE_URL}/qps/rest/2.0/search/am/hostasset"
    auth     = HTTPBasicAuth(USERNAME, PASSWORD)
    page     = 1
    last_id  = None        # cursor: ID of the last host received
    all_hosts = []

    while True:
        log.info(f"Fetching EC2 assets — page {page} (cursor id={last_id or 'start'})")
        response = session.post(
            url,
            headers={"Content-Type": "text/xml", "Accept": "application/xml"},
            auth=auth,
            data=build_ec2_fetch_request(last_id=last_id),
            verify=CERT_PATH
        )
        response.raise_for_status()

        root     = ET.fromstring(response.content)
        hosts    = root.findall(".//HostAsset")

        if not hosts:
            break

        all_hosts.extend(hosts)
        log.info(f"  → received {len(hosts)} hosts (total so far: {len(all_hosts)})")

        has_more = root.findtext(".//hasMoreRecords", "")
        if str(has_more).lower() != "true":
            break

        # advance cursor to the last received host ID
        last_id = hosts[-1].findtext("id", "").strip()
        if not last_id:
            log.warning("Could not read last host ID — stopping pagination")
            break

        page += 1

    log.info(f"Total EC2 hosts fetched: {len(all_hosts)}")
    return all_hosts


# ─────────────────────────── FLATTEN & DATAFRAME ───────────────────────────
def flatten_element(element: ET.Element, prefix: str = "") -> Dict[str, str]:
    """Recursively flatten an XML element into a dict of col_name -> value."""
    result = {}
    children = list(element)

    if not children:
        value = (element.text or "").strip()
        if prefix:
            result[prefix] = value
        return result

    grouped = defaultdict(list)
    for child in children:
        grouped[child.tag].append(child)

    for tag, siblings in grouped.items():
        column_name = f"{prefix}.{tag}" if prefix else tag

        if len(siblings) == 1:
            child = siblings[0]
            if list(child):
                result.update(flatten_element(child, column_name))
            else:
                result[column_name] = (child.text or "").strip()
        else:
            values = []
            for item in siblings:
                values.append(", ".join(v for v in flatten_element(item).values() if v))
            result[column_name] = " | ".join(values)

    return result


def build_dataframe(hosts: List[ET.Element]) -> pd.DataFrame:
    """Convert list of HostAsset XML elements into a flat DataFrame."""
    rows = []
    for host in hosts:
        rows.append(flatten_element(host))

    df = pd.DataFrame(rows)
    df.fillna("", inplace=True)

    if EC2_RAW_COL in df.columns:
        df.insert(0, "EC2 Instance ID", df[EC2_RAW_COL])
    else:
        df.insert(0, "EC2 Instance ID", "")

    priority_columns = ["id", "address", EC2_RAW_COL]
    front = [col for col in priority_columns if col in df.columns]
    remaining = [col for col in df.columns if col not in front]
    df = df[front + sorted(remaining)]
    return df


# ─────────────────────────── EXPORT ───────────────────────────
def export_excel(df: pd.DataFrame) -> str:
    """Save the full assets DataFrame to Excel."""
    output_file = "qualys_assets.xlsx"
    df.to_excel(output_file, sheet_name="Assets", index=False)
    log.info(f"Saved: {output_file}")
    return output_file


def match_dead_instances(df: pd.DataFrame, found_ids: List[str]) -> pd.DataFrame:
    """Cross-reference dead EC2 instance IDs against the Qualys assets DataFrame."""
    if EC2_RAW_COL not in df.columns:
        log.warning(f"Column '{EC2_RAW_COL}' not found in dataframe")
        return pd.DataFrame(columns=["Qualys ID", "address", "EC2 Instance ID"])

    found_set = {str(i).strip() for i in found_ids if str(i).strip()}
    matched = df[df[EC2_RAW_COL].astype(str).str.strip().isin(found_set)]

    result = pd.DataFrame({
        "Qualys ID":      matched["id"] if "id" in matched.columns else "",
        "address":        matched["address"] if "address" in matched.columns else "",
        "EC2 Instance ID": matched[EC2_RAW_COL],
    })
    log.info(f"Matched dead instances in Qualys: {len(result)}")
    return result


def export_matched_excel(df: pd.DataFrame) -> str:
    """Save the matched dead-instance DataFrame to Excel."""
    output_file = "qualys_dead_matches.xlsx"
    df.to_excel(output_file, sheet_name="DeadMatches", index=False)
    log.info(f"Saved: {output_file}")
    return output_file


# ─────────────────────────── MAIN ───────────────────────────
def main():
    session = requests.Session()
    try:
        dead_instances = get_dead_instance_dicts(
            FILEPATH,
            id_column="Resource ID",
            status_column="State"
        )
        found_ids = [item["Resource ID"] for item in dead_instances]

        if not found_ids:
            log.info("No dead instances found in input files")
            return

        login(session)

        hosts = fetch_all_hosts(session)
        if not hosts:
            log.info("No assets found in Qualys")
            return

        df = build_dataframe(hosts)
        matched_df = match_dead_instances(df, found_ids)

        if matched_df.empty:
            log.info("No matching assets found in Qualys")
            return

        export_matched_excel(matched_df)

    finally:
        logout(session)


if __name__ == "__main__":
    main()
